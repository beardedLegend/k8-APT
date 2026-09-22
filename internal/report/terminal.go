// Package report renders the result of a run: a colored summary for the
// terminal and a markdown document for sharing or for CI artefacts.
package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/budget"
	"github.com/beardedLegend/k8-apt/internal/scenarios"
)

// ---------------------------------------------------------------------------
// Terminal report: a compact, colored summary printed to stdout at the end of
// a run. Markdown() renders the same thing for a file.
// ---------------------------------------------------------------------------

// forceColor overrides colour auto-detection (--color=always|never).
var forceColor *bool

// SetColor forces colour on or off; nil restores auto-detection.
func SetColor(v *bool) { forceColor = v }

type palette struct {
	reset, bold, dim                     string
	green, red, yellow, cyan, gray, blue string
}

func colors() palette {
	if !colorEnabled() {
		return palette{}
	}
	return palette{
		reset:  "\033[0m",
		bold:   "\033[1m",
		dim:    "\033[2m",
		green:  "\033[32m",
		red:    "\033[31m",
		yellow: "\033[33m",
		cyan:   "\033[36m",
		gray:   "\033[90m",
		blue:   "\033[34m",
	}
}

func colorEnabled() bool {
	if forceColor != nil {
		return *forceColor
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	m := fi.Mode()
	// Real terminal (char device) or a pipe (how `go test` captures stdout).
	// A redirect to a regular file gets no color.
	return m&os.ModeCharDevice != 0 || m&os.ModeNamedPipe != 0
}

type reqCounts struct{ pass, fail, diff, gap, skip int }

// printTerminalReport renders the run summary to stdout.
// Terminal prints the run summary to stdout.
func Terminal(env *audit.Env, events []*audit.Event, results []*audit.Result, b *budget.Budget) {
	c := colors()
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format, args...) }

	const width = 74
	line := strings.Repeat("─", width)

	// ---- header ---------------------------------------------------------
	w("\n%s%s╭%s╮%s\n", c.bold, c.cyan, line, c.reset)
	title := "KUBERNETES AUDIT POLICY TEST"
	sub := fmt.Sprintf("run %s · %s", env.RunID, env.Start.UTC().Format("2006-01-02 15:04Z"))
	w("%s%s│%s %s%-*s%s %s│%s\n", c.bold, c.cyan, c.reset, c.bold, width-2, title, c.reset, c.cyan+c.bold, c.reset)
	w("%s%s│%s %s%-*s%s %s│%s\n", c.bold, c.cyan, c.reset, c.dim, width-2, sub, c.reset, c.cyan+c.bold, c.reset)
	src := fmt.Sprintf("%d events · %s", len(events), env.Logs.Describe())
	w("%s%s│%s %s%-*s%s %s│%s\n", c.bold, c.cyan, c.reset, c.dim, width-2, audit.Truncate(src, width-2), c.reset, c.cyan+c.bold, c.reset)
	w("%s%s╰%s╯%s\n\n", c.bold, c.cyan, line, c.reset)

	// ---- coverage table -------------------------------------------------
	byReq := map[string]*reqCounts{}
	var totals reqCounts
	for _, r := range results {
		req := r.Expect.Requirement
		if req == "" {
			req = "(unassigned)"
		}
		rc := byReq[req]
		if rc == nil {
			rc = &reqCounts{}
			byReq[req] = rc
		}
		switch r.Status() {
		case "PASS", "GAP-CLOSED":
			rc.pass++
			totals.pass++
		case "FAIL":
			rc.fail++
			totals.fail++
		case "DIFF":
			rc.diff++
			totals.diff++
		case "GAP":
			rc.gap++
			totals.gap++
		case "SKIP":
			rc.skip++
			totals.skip++
		}
	}
	order := append([]string{}, scenarios.RequirementOrder...)
	for req := range byReq {
		if !audit.Contains(order, req) {
			order = append(order, req)
		}
	}

	reqW := 20
	for _, req := range order {
		if byReq[req] != nil && len(req) > reqW {
			reqW = len(req)
		}
	}
	if reqW > 48 {
		reqW = 48
	}

	w("%s  COVERAGE BY REQUIREMENT%s\n", c.bold, c.reset)
	header := fmt.Sprintf("  %-*s  %4s %4s %4s %4s %4s", reqW, "requirement", "pass", "fail", "diff", "gap", "skip")
	w("%s%s%s\n", c.dim, header, c.reset)
	w("%s  %s%s\n", c.dim, strings.Repeat("─", reqW+2+5*5), c.reset)
	for _, req := range order {
		rc := byReq[req]
		if rc == nil {
			continue
		}
		glyph, col := rowStatus(c, rc)
		num := func(n int, hot string) string {
			if n == 0 {
				return fmt.Sprintf("%s%4d%s", c.dim, n, c.reset)
			}
			return fmt.Sprintf("%s%4d%s", hot, n, c.reset)
		}
		w("  %s%-*s%s  %s %s %s %s %s  %s%s%s\n",
			col, reqW, audit.Truncate(req, reqW), c.reset,
			num(rc.pass, c.green), num(rc.fail, c.red), num(rc.diff, c.blue), num(rc.gap, c.yellow), num(rc.skip, c.gray),
			col, glyph, c.reset)
	}
	w("\n")

	// ---- findings -------------------------------------------------------
	var fails, diffs, gaps, skips []*audit.Result
	for _, r := range results {
		switch r.Status() {
		case "FAIL":
			fails = append(fails, r)
		case "DIFF":
			diffs = append(diffs, r)
		case "GAP":
			gaps = append(gaps, r)
		case "SKIP":
			skips = append(skips, r)
		}
	}
	printFindingGroup(&sb, c, c.red, "✗ FAILURES (policy does not meet the requirement)", fails, 6)
	printFindingGroup(&sb, c, c.blue, "≠ DIFFERS FROM THE BASELINE POLICY (--strict fails on these)", diffs, 2)
	printFindingGroup(&sb, c, c.yellow, "⚠ KNOWN GAPS (documented limitations, non-fatal)", gaps, 2)
	printFindingGroup(&sb, c, c.gray, "○ SKIPPED (scenario could not run)", skips, 1)

	// ---- log composition ------------------------------------------------
	levels := map[string]int{}
	hosts := map[string]int{}
	users := map[string]int{}
	bodies := 0
	for _, e := range events {
		levels[e.Level]++
		hosts[e.Host]++
		users[e.User.Username]++
		if len(e.RequestObject) > 0 || len(e.ResponseObject) > 0 {
			bodies++
		}
	}
	w("%s  WHAT THE LOG CONTAINED%s\n", c.bold, c.reset)
	w("  %slevels%s   %s\n", c.dim, c.reset, levelBar(c, levels, len(events)))
	w("  %sbodies%s   %d of %d events carry a request/response body\n", c.dim, c.reset, bodies, len(events))
	w("  %smasters%s  %s\n", c.dim, c.reset, audit.FmtCounts(hosts, 0))
	w("  %stop 5%s    ", c.dim, c.reset)
	top := audit.SortedCounts(users, 5)
	var parts []string
	for _, kv := range top {
		parts = append(parts, fmt.Sprintf("%s (%d)", audit.ShortUser(kv.Key), kv.Count))
	}
	w("%s\n\n", strings.Join(parts, ", "))

	// ---- log volume budget ----------------------------------------------
	if b != nil {
		w("%s", budgetSection(b, c))
	}

	// ---- verdict --------------------------------------------------------
	var verdict, vcol string
	switch {
	case totals.fail > 0:
		verdict, vcol = "FAIL", c.red
	case totals.diff > 0:
		verdict, vcol = "PASS (differs from the baseline policy)", c.blue
	case totals.gap > 0:
		verdict, vcol = "PASS (with known gaps)", c.yellow
	default:
		verdict, vcol = "PASS", c.green
	}
	w("%s%s  %s  %s", c.bold, vcol, verdict, c.reset)
	w("%s  %d passing · %d failing · %d differing · %d gaps · %d skipped%s\n",
		c.dim, totals.pass, totals.fail, totals.diff, totals.gap, totals.skip, c.reset)
	if totals.fail > 0 {
		w("  %s→ each ✗ above is an actionable policy bug; fix the rule and re-run.%s\n", c.dim, c.reset)
	}
	w("\n")

	fmt.Fprint(os.Stdout, sb.String())
}

func rowStatus(c palette, rc *reqCounts) (glyph, col string) {
	switch {
	case rc.fail > 0:
		return "✗", c.red
	case rc.diff > 0:
		return "≠", c.blue
	case rc.gap > 0:
		return "⚠", c.yellow
	case rc.pass == 0 && rc.skip > 0:
		return "○", c.gray
	default:
		return "✓", c.green
	}
}

func printFindingGroup(b *strings.Builder, c palette, col, heading string, rs []*audit.Result, maxLines int) {
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(b, "%s%s  %s (%d)%s\n", c.bold, col, heading, len(rs), c.reset)
	for _, r := range rs {
		fmt.Fprintf(b, "  %s•%s %s%s%s  %s\n", col, c.reset, c.bold, r.Scenario, c.reset, r.Expect.Desc)
		shown := 0
		for _, e := range r.Errors {
			if shown >= maxLines {
				fmt.Fprintf(b, "      %s… %d more%s\n", c.dim, len(r.Errors)-shown, c.reset)
				break
			}
			fmt.Fprintf(b, "      %s%s%s\n", c.dim, audit.Truncate(e, 96), c.reset)
			shown++
		}
		if r.Skipped != "" {
			fmt.Fprintf(b, "      %s%s%s\n", c.dim, audit.Truncate(r.Skipped, 96), c.reset)
		}
	}
	fmt.Fprint(b, "\n")
}

// levelBar renders "Metadata 161 ▏███████░░░  Request 92 ▏████░░" style counts.
func levelBar(c palette, levels map[string]int, total int) string {
	if total == 0 {
		return ""
	}
	order := []string{"None", "Metadata", "Request", "RequestResponse"}
	colOf := map[string]string{"Metadata": c.cyan, "Request": c.yellow, "RequestResponse": c.red, "None": c.gray}
	var seen []string
	for _, l := range order {
		if levels[l] > 0 {
			seen = append(seen, l)
		}
	}
	for l := range levels {
		if !audit.Contains(order, l) {
			seen = append(seen, l)
		}
	}
	var parts []string
	for _, l := range seen {
		n := levels[l]
		bars := n * 12 / total
		if bars == 0 && n > 0 {
			bars = 1
		}
		bar := colOf[l] + strings.Repeat("█", bars) + c.dim + strings.Repeat("░", 12-bars) + c.reset
		parts = append(parts, fmt.Sprintf("%s%-8s%s %s %4d", c.bold, l, c.reset, bar, n))
	}
	return strings.Join(parts, "  ")
}

// budgetSection renders the log volume budget for the terminal report.
func budgetSection(b *budget.Budget, c palette) string {
	var s strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&s, format, args...) }
	idle := b.IdleGBPerYear()
	col := c.green
	if idle > b.GBPerYear {
		col = c.red
	} else if idle > b.GBPerYear*0.7 {
		col = c.yellow
	}
	w("%s  LOG VOLUME BUDGET%s  %s%.1f GB/year = %s/day%s\n", c.bold, c.reset, c.dim, b.GBPerYear, budget.MB(b.BudgetBytesPerDay()), c.reset)
	w("  %sidle%s     %s%s/day → %.2f GB/year%s  %s(%d background events in %s)%s\n",
		c.dim, c.reset, col, budget.MB(b.BytesPerDay(b.Background.Bytes)), idle, c.reset, c.dim, b.Background.Events, b.Sample.Round(time.Second), c.reset)
	hb, he := b.Headroom()
	w("  %sheadroom%s %s/day ≈ %.0f events of this run's average size\n", c.dim, c.reset, budget.MB(hb), he)
	w("  %srun%s      %d events, %s  %s(%s)%s\n", c.dim, c.reset, b.Run.Events, budget.MB(float64(b.Run.Bytes)), c.dim, budget.LevelVolumes(b.RunByLevel), c.reset)
	if len(b.TopBackground) > 0 {
		w("  %snoise%s    ", c.dim, c.reset)
		var parts []string
		for i, kv := range b.TopBackground {
			if i == 4 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s %s", budget.MB(b.BytesPerDay(kv.Count))+"/d", kv.Key))
		}
		w("%s\n", audit.Truncate(strings.Join(parts, " · "), 200))
	}
	if !b.Clean {
		w("  %sbaseline is the run itself (%s), reactions to the run count as idle; --idle-sample 10m gives a clean figure%s\n", c.dim, b.Sample.Round(time.Second), c.reset)
	} else if b.Sample < 5*time.Minute {
		w("  %sidle sample is only %s; --idle-sample 10m gives a steadier figure%s\n", c.dim, b.Sample.Round(time.Second), c.reset)
	}
	w("\n")
	return s.String()
}
