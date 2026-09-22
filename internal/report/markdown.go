package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/your-org/k8-apt/internal/audit"
	"github.com/your-org/k8-apt/internal/budget"
	"github.com/your-org/k8-apt/internal/scenarios"
)

// Markdown renders the full report: the shareable form of what Terminal
// prints, without colour codes.
func Markdown(env *audit.Env, events []*audit.Event, results []*audit.Result, bud *budget.Budget) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	p("# Kubernetes audit policy report\n\n")
	p("Run `%s` at %s · %d audit events in the window · identity `%s` · log source `%s`\n\n",
		env.RunID, env.Start.UTC().Format(time.RFC3339), len(events), env.AdminUser, env.Logs.Describe())

	type counts struct{ pass, fail, diff, gap, closed, skip int }
	byReq := map[string]*counts{}
	for _, r := range results {
		req := r.Expect.Requirement
		if req == "" {
			req = "(unassigned)"
		}
		c := byReq[req]
		if c == nil {
			c = &counts{}
			byReq[req] = c
		}
		switch r.Status() {
		case "PASS":
			c.pass++
		case "FAIL":
			c.fail++
		case "DIFF":
			c.diff++
		case "GAP":
			c.gap++
		case "GAP-CLOSED":
			c.closed++
		case "SKIP":
			c.skip++
		}
	}
	p("## Coverage by requirement\n\n")
	p("| Requirement | pass | fail | differs | known gap | skipped |\n|---|---:|---:|---:|---:|---:|\n")
	order := append([]string{}, scenarios.RequirementOrder...)
	for req := range byReq {
		if !audit.Contains(order, req) {
			order = append(order, req)
		}
	}
	for _, req := range order {
		c := byReq[req]
		if c == nil {
			continue
		}
		p("| %s | %d | %d | %d | %d | %d |\n", req, c.pass+c.closed, c.fail, c.diff, c.gap, c.skip)
	}

	p("\n## Findings\n\n")
	p("`FAIL` breaks a requirement, `DIFF` differs from the baseline policy (which may be deliberate), `GAP` is a documented limitation, `SKIP` could not run.\n\n")
	anyFinding := false
	for _, r := range results {
		st := r.Status()
		if st == "PASS" {
			continue
		}
		anyFinding = true
		p("- **%s** `%s`: %s\n", st, r.Scenario, r.Expect.Desc)
		for _, e := range r.Errors {
			p("  - %s\n", e)
		}
		if r.Expect.Gap != "" {
			p("  - gap: %s\n", r.Expect.Gap)
		}
		if r.Skipped != "" {
			p("  - %s\n", r.Skipped)
		}
	}
	if !anyFinding {
		p("none\n")
	}

	p("\n## What the log contained during the run\n\n")
	levels := map[string]int{}
	users := map[string]int{}
	hosts := map[string]int{}
	bodies := 0
	for _, e := range events {
		levels[e.Level]++
		users[e.User.Username]++
		hosts[e.Host]++
		if len(e.RequestObject) > 0 || len(e.ResponseObject) > 0 {
			bodies++
		}
	}
	p("Events by level: %s; %d events carry a body.\n\n", audit.FmtCounts(levels, 0), bodies)
	p("Events by master: %s\n\n", audit.FmtCounts(hosts, 0))
	p("Top users:\n\n| user | events |\n|---|---:|\n")
	for _, kv := range audit.SortedCounts(users, 20) {
		p("| %s | %d |\n", kv.Key, kv.Count)
	}

	p("\n%s", bud.Markdown())
	return b.String()
}
