// Package runner drives one run end to end: act on the cluster, read the
// audit log, check every expectation, report.
package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/budget"
	"github.com/beardedLegend/k8-apt/internal/config"
	"github.com/beardedLegend/k8-apt/internal/report"
	"github.com/beardedLegend/k8-apt/internal/scenarios"
)

// Options are the run-time knobs that are not properties of the cluster.
type Options struct {
	// Strict makes a failed baseline expectation fail the run. Without it
	// only invariants (and hard errors) are fatal, and differences from the
	// baseline policy are reported as such.
	Strict bool
	// Only, when non-empty, limits the run to scenarios whose name contains
	// one of these substrings. The namespace scenarios always run.
	Only []string
	// EventsFile, ReportFile: where to write the raw events (JSON lines) and
	// the markdown report.
	EventsFile string
	ReportFile string
	// Log receives progress lines. Nil discards them.
	Log func(format string, args ...any)
	// Observe is called for every checked expectation, in order. It lets the
	// go test entry point turn each into a subtest.
	Observe func(r *audit.Result)
}

// Result is the outcome of a run.
type Result struct {
	Env     *audit.Env
	Events  []*audit.Event
	Results []*audit.Result
	Budget  *budget.Budget
	// ActErrors holds the scenarios whose Act failed, Skipped those that
	// could not run at all.
	ActErrors map[string]string
	Skipped   map[string]string
	// FetchedAt is when the log was read and Scenarios how many scenarios
	// ran: the inputs of the budget, kept so it can be recomputed.
	FetchedAt time.Time
	Scenarios int
}

// Counts summarises the results.
type Counts struct{ Pass, Fail, Diff, Gap, Skip int }

func (r *Result) Counts() Counts {
	var c Counts
	for _, x := range r.Results {
		switch x.Status() {
		case "PASS", "GAP-CLOSED":
			c.Pass++
		case "FAIL":
			c.Fail++
		case "DIFF":
			c.Diff++
		case "GAP":
			c.Gap++
		case "SKIP":
			c.Skip++
		}
	}
	return c
}

// Failed reports whether the run found something that must fail it.
func (r *Result) Failed() bool { return r.Counts().Fail > 0 }

// Run performs a whole run against the cluster described by cfg.
func Run(ctx context.Context, cfg *config.Cluster, opt Options) (*Result, error) {
	logf := opt.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	env, err := audit.NewEnv(ctx, cfg)
	if err != nil {
		return nil, err
	}
	logf("run %s: namespace %s, identity %s, log source %s",
		env.RunID, env.Namespace, env.AdminUser, env.Logs.Describe())

	if err := env.Logs.Begin(ctx); err != nil {
		return nil, fmt.Errorf("read the current log position: %w", err)
	}
	defer cleanup(env, logf)

	if d := cfg.IdleSample.Duration(); d > 0 {
		logf("idling %s to sample the cluster's background log volume", d)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// ---- act -------------------------------------------------------------
	env.ActStart = time.Now()
	all := scenarios.Scenarios(env)
	run := filter(all, opt.Only)
	res := &Result{Env: env, ActErrors: map[string]string{}, Skipped: map[string]string{}}
	for _, s := range run {
		actx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		started := time.Now()
		err := s.Act(actx, env)
		cancel()
		switch {
		case err == nil:
			logf("  %-40s ok (%s)", s.Name, time.Since(started).Round(time.Millisecond))
		case s.Optional:
			res.Skipped[s.Name] = err.Error()
			logf("  %-40s skipped: %v", s.Name, err)
		default:
			res.ActErrors[s.Name] = err.Error()
			logf("  %-40s FAILED: %v", s.Name, err)
		}
	}

	// ---- fetch -----------------------------------------------------------
	time.Sleep(cfg.Settle.Duration())
	fetched, err := env.Logs.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch the audit log: %w", err)
	}
	fetchedAt := time.Now()
	res.FetchedAt, res.Scenarios = fetchedAt, len(run)
	window := env.Start.Add(-2 * time.Minute)
	for _, e := range fetched {
		if e.RequestReceived.After(window) {
			res.Events = append(res.Events, e)
		}
	}
	logf("fetched %d events (%d since %s)", len(fetched), len(res.Events), window.UTC().Format(time.RFC3339))
	if len(res.Events) == 0 {
		return nil, fmt.Errorf("no audit events were read from %s: is audit logging enabled and is the log path right?", env.Logs.Describe())
	}
	if opt.EventsFile != "" {
		var b strings.Builder
		for _, e := range res.Events {
			b.WriteString(e.Raw)
			b.WriteByte('\n')
		}
		if err := os.WriteFile(opt.EventsFile, []byte(b.String()), 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", opt.EventsFile, err)
		}
	}

	// ---- verify ----------------------------------------------------------
	record := func(r *audit.Result) {
		res.Results = append(res.Results, r)
		if opt.Observe != nil {
			opt.Observe(r)
		}
	}
	for _, s := range run {
		for _, ex := range s.Expect(env) {
			r := audit.Verify(s.Name, ex, res.Events, env.UserAgent, opt.Strict)
			if msg, ok := res.Skipped[s.Name]; ok {
				r.Skipped = "scenario skipped: " + msg
			} else if msg, ok := res.ActErrors[s.Name]; ok {
				r.Skipped = "scenario act failed: " + msg
			}
			record(r)
		}
	}
	if len(opt.Only) == 0 {
		for _, ex := range scenarios.GlobalExpectations(env) {
			record(audit.Verify("global", ex, res.Events, env.UserAgent, opt.Strict))
		}
	}
	for _, r := range scenarios.LogChecks(env, res.Events, opt.Strict) {
		record(r)
	}

	res.Budget = budget.Compute(env, res.Events, fetchedAt, len(run))
	record(&audit.Result{
		Scenario: "global",
		Expect: audit.Expect{
			Desc:        res.Budget.Desc(),
			Requirement: scenarios.ReqBudget,
		},
		Errors: res.Budget.Check(),
		Strict: opt.Strict,
	})

	if opt.ReportFile != "" {
		if err := os.WriteFile(opt.ReportFile, []byte(report.Markdown(res.Env, res.Events, res.Results, res.Budget)), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", opt.ReportFile, err)
		}
		logf("report written to %s", opt.ReportFile)
	}
	return res, nil
}

// filter keeps the scenarios the user asked for, plus the namespace ones that
// everything else depends on.
func filter(all []scenarios.Scenario, only []string) []scenarios.Scenario {
	if len(only) == 0 {
		return all
	}
	var out []scenarios.Scenario
	for _, s := range all {
		keep := strings.HasPrefix(s.Name, "namespace-")
		for _, want := range only {
			if strings.Contains(s.Name, want) {
				keep = true
			}
		}
		if keep {
			out = append(out, s)
		}
	}
	return out
}

// cleanup removes everything a run may have left behind. Objects the
// scenarios delete themselves are simply not found here.
func cleanup(env *audit.Env, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	try := func(what string, err error) {
		if err != nil && !isNotFound(err) {
			logf("cleanup %s: %v", what, err)
		}
	}
	scenarios.Cleanup(ctx, env, try)
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// Report prints the terminal summary of a finished run.
func Report(res *Result) {
	report.Terminal(res.Env, res.Events, res.Results, res.Budget)
}

// ListScenarios returns the names of the scenarios that apply to a cluster
// profile, without touching the cluster.
func ListScenarios(cfg *config.Cluster) []string {
	env := &audit.Env{Cfg: cfg, Domain: cfg.TestDomain, Image: cfg.Image}
	var out []string
	for _, s := range scenarios.Scenarios(env) {
		name := s.Name
		if s.Optional {
			name += "  (optional)"
		}
		out = append(out, name)
	}
	return out
}
