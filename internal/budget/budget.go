package budget

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

// ---------------------------------------------------------------------------
// Log volume budget
//
// The audit log of a cluster must stay within a yearly size budget (default
// 36.5 GB per cluster per year = 100 MB per day). Human activity must be
// logged whatever it costs, so the budget is really a constraint on what the
// policy lets through when nobody is working: the background noise of
// controllers, kubelets, probes and operators.
//
// A run measures that noise: every event fetched from the masters that was
// not caused by the run (neither carries the run's User-Agent nor mentions
// the run id, which every test object and namespace name contains) is
// background, and its byte volume over the sampled wall-clock time is
// extrapolated to a day and a year. Events caused by the run are reported
// separately, as the cost of a burst of human activity.
//
// With --idle-sample set the baseline is the quiet window before the
// first scenario acts, which is the clean measurement. Without it the whole
// run serves as the sample, which is short and contaminated by reactions to
// the run that do not mention the run id (Calico IPAM writes for the test
// pods, for instance), so the figure is only indicative and the report says
// so. budget.gbPerYear in the cluster profile sets the budget.
// ---------------------------------------------------------------------------

// Volume is a number of events and the bytes they occupy.
type Volume struct {
	Events int
	Bytes  int
}

type Budget struct {
	GBPerYear float64
	// Scenarios is how many scenarios produced the run volume.
	Scenarios int
	Sample    time.Duration
	// Clean is true when the sample is the idle window before the run acted.
	Clean bool

	Background Volume
	Run        Volume
	// BackgroundByLevel / RunByLevel split the volumes per audit level.
	BackgroundByLevel map[string]Volume
	RunByLevel        map[string]Volume
	// TopBackground lists the largest background contributors as
	// "user verb resource" with their byte volume in the sample.
	TopBackground []audit.KV
	// TopRun lists the largest contributors of the run the same way.
	TopRun []audit.KV
}

// causedByRun reports whether an event was produced by the test run itself
// or by a controller reacting to one of its objects.
func causedByRun(env *audit.Env, e *audit.Event) bool {
	return e.UserAgent == env.UserAgent || strings.Contains(e.Raw, env.RunID)
}

func eventKey(e *audit.Event) string {
	what := e.Resource()
	if e.Subresource() != "" {
		what += "/" + e.Subresource()
	}
	if what == "" {
		what = strings.SplitN(e.RequestURI, "?", 2)[0]
	}
	return audit.ShortUser(e.User.Username) + " " + e.Verb + " " + what
}

// Compute measures the log volume of a finished run.
func Compute(env *audit.Env, events []*audit.Event, fetchedAt time.Time, scenarioCount int) *Budget {
	b := &Budget{
		GBPerYear:         env.Cfg.Budget.GBPerYear,
		Sample:            fetchedAt.Sub(env.Start),
		BackgroundByLevel: map[string]Volume{},
		RunByLevel:        map[string]Volume{},
		Scenarios:         scenarioCount,
	}
	// Background is sampled over the idle window if there was one long
	// enough, otherwise over the whole run.
	bgEnd := fetchedAt
	if !env.ActStart.IsZero() && env.ActStart.Sub(env.Start) >= 30*time.Second {
		b.Clean = true
		b.Sample = env.ActStart.Sub(env.Start)
		bgEnd = env.ActStart
	}
	bg := map[string]int{}
	run := map[string]int{}
	for _, e := range events {
		if e.RequestReceived.Before(env.Start) {
			continue
		}
		n := len(e.Raw) + 1 // newline
		if causedByRun(env, e) {
			b.Run.Events++
			b.Run.Bytes += n
			v := b.RunByLevel[e.Level]
			v.Events++
			v.Bytes += n
			b.RunByLevel[e.Level] = v
			run[eventKey(e)] += n
			continue
		}
		if !e.RequestReceived.Before(bgEnd) {
			continue // after the idle window: reactions to the run, not baseline
		}
		b.Background.Events++
		b.Background.Bytes += n
		v := b.BackgroundByLevel[e.Level]
		v.Events++
		v.Bytes += n
		b.BackgroundByLevel[e.Level] = v
		bg[eventKey(e)] += n
	}
	b.TopBackground = audit.SortedCounts(bg, 8)
	b.TopRun = audit.SortedCounts(run, 5)
	return b
}

// BytesPerDay extrapolates a byte count of the sample to a day.
func (b *Budget) BytesPerDay(n int) float64 {
	if b.Sample <= 0 {
		return 0
	}
	return float64(n) / b.Sample.Seconds() * 86400
}

func (b *Budget) IdleGBPerYear() float64 {
	return b.BytesPerDay(b.Background.Bytes) * 365 / 1e9
}

func (b *Budget) BudgetBytesPerDay() float64 {
	return b.GBPerYear * 1e9 / 365
}

// Headroom is what is left of the daily budget for real activity once the
// idle noise is subtracted, and how many events of the run's average size
// that buys per day.
func (b *Budget) Headroom() (bytesPerDay float64, eventsPerDay float64) {
	bytesPerDay = b.BudgetBytesPerDay() - b.BytesPerDay(b.Background.Bytes)
	if b.Run.Events > 0 {
		eventsPerDay = bytesPerDay / (float64(b.Run.Bytes) / float64(b.Run.Events))
	}
	return
}

// Check returns the verification errors for the budget expectation.
func (b *Budget) Check() []string {
	var errs []string
	if b.Sample < 30*time.Second {
		return []string{fmt.Sprintf("sample of %s too short to extrapolate", b.Sample.Round(time.Second))}
	}
	if !b.Clean {
		// Only a clean idle sample is precise enough to fail the run on.
		return nil
	}
	if idle := b.IdleGBPerYear(); idle > b.GBPerYear {
		errs = append(errs, fmt.Sprintf("idle cluster writes %.1f GB/year (%.1f MB/day), budget is %.1f GB/year (%.0f MB/day)",
			idle, b.BytesPerDay(b.Background.Bytes)/1e6, b.GBPerYear, b.BudgetBytesPerDay()/1e6))
		for _, kv := range b.TopBackground {
			if len(errs) > 4 {
				break
			}
			errs = append(errs, fmt.Sprintf("  %.1f MB/day  %s", b.BytesPerDay(kv.Count)/1e6, kv.Key))
		}
	}
	return errs
}

func (b *Budget) Desc() string {
	d := fmt.Sprintf("idle log volume stays within %.1f GB per cluster per year (%.0f MB/day)", b.GBPerYear, b.BudgetBytesPerDay()/1e6)
	if !b.Clean {
		d += " (not checked: no --idle-sample, see the budget section)"
	}
	return d
}

// MB renders a byte count in human units.
func MB(n float64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.2f GB", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f MB", n/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.0f KB", n/1e3)
	default:
		return fmt.Sprintf("%.0f B", n)
	}
}

// LevelVolumes renders "Metadata 12 ev/3.4 KB, Request 2 ev/1.1 KB".
func LevelVolumes(m map[string]Volume) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := m[k]
		parts = append(parts, fmt.Sprintf("%s %d ev/%s", k, v.Events, MB(float64(v.Bytes))))
	}
	return strings.Join(parts, ", ")
}

func (b *Budget) Markdown() string {
	var s strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&s, format, args...) }
	p("## Log volume budget\n\n")
	p("Budget: %.1f GB per cluster per year = %s per day. Baseline sampled over %s", b.GBPerYear, MB(b.BudgetBytesPerDay()), b.Sample.Round(time.Second))
	if b.Clean {
		p(" of idle cluster before the run acted")
	} else {
		p(" of the run itself (indicative only: reactions to the run count as background; use `--idle-sample 10m` for a clean baseline)")
	}
	p(".\n\n")
	p("| | events | bytes in sample | extrapolated per day | per year |\n|---|---:|---:|---:|---:|\n")
	p("| background (not caused by the run) | %d | %s | %s | %.2f GB |\n", b.Background.Events, MB(float64(b.Background.Bytes)), MB(b.BytesPerDay(b.Background.Bytes)), b.IdleGBPerYear())
	p("| this run (%d scenarios of activity) | %d | %s | – | – |\n", b.Scenarios, b.Run.Events, MB(float64(b.Run.Bytes)))
	hb, he := b.Headroom()
	p("\nHeadroom after idle noise: %s per day ≈ %.0f events of this run's average size (%s).\n\n",
		MB(hb), he, MB(float64(b.Run.Bytes)/float64(max(b.Run.Events, 1))))
	p("Background by level: %s\n\nRun by level: %s\n\n", LevelVolumes(b.BackgroundByLevel), LevelVolumes(b.RunByLevel))
	p("Largest background contributors:\n\n| per day | user verb resource |\n|---:|---|\n")
	for _, kv := range b.TopBackground {
		p("| %s | %s |\n", MB(b.BytesPerDay(kv.Count)), kv.Key)
	}
	p("\nLargest contributors of the run:\n\n| bytes | user verb resource |\n|---:|---|\n")
	for _, kv := range b.TopRun {
		p("| %s | %s |\n", MB(float64(kv.Count)), kv.Key)
	}
	p("\n")
	return s.String()
}
