// Package policygen turns the findings of a run into an audit policy that
// closes them: one rule per kind of request a failing check is about,
// placed ahead of the cluster's own rules.
//
// Every candidate rule is tried against the run's own events before it is
// kept. The simulation re-levels each event the rule matches, re-checks
// every expectation of the run, and keeps the rule only if it fixes at least
// one finding and turns no passing check into a finding. A rule that would
// break something is reported with what it would break, not written.
package policygen

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/auditpolicy"
	"github.com/beardedLegend/k8-apt/internal/budget"
	"github.com/beardedLegend/k8-apt/internal/scenarios"
	"github.com/beardedLegend/k8-apt/policy"
)

// Input is a finished run.
type Input struct {
	Env       *audit.Env
	Events    []*audit.Event
	Results   []*audit.Result
	FetchedAt time.Time
	Scenarios int
	Strict    bool
}

// Options choose what to fix and what to extend.
type Options struct {
	// Policy is the policy the cluster runs. Nil means the embedded
	// baseline, which the default expectations describe.
	Policy []byte
	// Fix lists the statuses to act on: any of FAIL, DIFF, GAP.
	Fix []string
}

// Proposal is a rule the plan keeps.
type Proposal struct {
	Rule auditpolicy.Rule
	// Fixes are the findings the simulation showed it fixes.
	Fixes []string
	// Targets are the findings it was derived from.
	Targets []string
	// Unverified: the rule is about requests the cluster's policy drops, so
	// the run never saw them and the simulation could not confirm the fix.
	Unverified bool
}

// Rejection is a rule the plan leaves out because it would break checks.
type Rejection struct {
	Rule    auditpolicy.Rule
	Targets []string
	Breaks  []string
}

// Open is a finding the plan does not fix, and why.
type Open struct {
	Finding string
	Reason  string
}

// Plan is the outcome: the rules to add, what they do, what stays open.
type Plan struct {
	// Guard: the credential rule goes first; GuardFixes are the findings it
	// fixes on its own (a leak), if any.
	Guard             bool
	GuardFixes        []string
	OmitManagedFields bool
	Accepted          []*Proposal
	Rejected          []Rejection
	Open              []Open

	Findings int
	Fixed    int

	// Background bytes per day of the idle log, before and after, and
	// whether the sample was the clean idle window.
	IdleBefore, IdleAfter float64
	IdleClean             bool

	// AssumedBaseline: no policy was given, the baseline was extended.
	AssumedBaseline bool
	// Output is the complete policy file.
	Output []byte
}

// check is one re-verifiable result of the run.
type check struct {
	res     *audit.Result
	name    string
	matched []int // indices into the events the matcher selects, ignoring levels
}

type engine struct {
	in      Input
	checks  []check
	logRes  []*audit.Result // LogChecks on the original events
	base    []bool          // passing, per check then per log check
	finding []bool
}

func passing(r *audit.Result) bool {
	s := r.Status()
	return s == "PASS" || s == "GAP-CLOSED"
}

func label(r *audit.Result) string { return r.Scenario + ": " + r.Expect.Desc }

// Generate builds the plan and the policy file.
func Generate(in Input, opt Options) (*Plan, error) {
	plan := &Plan{}
	original := opt.Policy
	if original == nil {
		original, plan.AssumedBaseline = policy.Baseline, true
	}
	if _, err := auditpolicy.Parse(original); err != nil {
		return nil, fmt.Errorf("the policy to extend: %w", err)
	}
	fix := map[string]bool{}
	for _, s := range opt.Fix {
		fix[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	en := newEngine(in)
	base := en.statuses(in.Events)
	for i, ok := range base {
		en.base = append(en.base, ok)
		en.finding = append(en.finding, !ok && fix[en.result(i).Status()])
	}

	// Candidates, deduplicated by rule, in the order they would be placed.
	type cand struct {
		rule    auditpolicy.Rule
		targets []int
	}
	var cands []*cand
	byKey := map[string]*cand{}
	wantOMF := false
	var omfTargets []int
	for i, isFinding := range en.finding {
		if !isFinding {
			continue
		}
		plan.Findings++
		r := en.result(i)
		switch {
		case r.Expect.Gap == scenarios.GapManagedFields || r.Expect.Desc == "bodies never contain managedFields":
			wantOMF = true
			omfTargets = append(omfTargets, i)
			continue
		case r.Expect.Desc == "secret values and issued tokens never appear in the log":
			k := key(guardRule)
			if byKey[k] == nil {
				byKey[k] = &cand{rule: guardRule}
				cands = append(cands, byKey[k])
			}
			byKey[k].targets = append(byKey[k].targets, i)
			continue
		}
		rule, reason := derive(in.Env, in.Events, r)
		if reason != "" {
			plan.Open = append(plan.Open, Open{Finding: label(r), Reason: reason})
			continue
		}
		k := key(rule)
		if byKey[k] == nil {
			byKey[k] = &cand{rule: rule}
			cands = append(cands, byKey[k])
		}
		byKey[k].targets = append(byKey[k].targets, i)
	}
	sort.SliceStable(cands, func(a, b int) bool { return before(cands[a].rule, cands[b].rule) })

	// Greedy: keep each candidate that fixes something and breaks nothing.
	fixed := map[int]bool{}
	var accepted []*Proposal
	try := func(guard, omf bool, extra *auditpolicy.Rule) (fixes, breaks []int) {
		rules := assemble(guard, accepted, extra)
		st := en.statuses(simulate(in.Events, rules, omf))
		for i, ok := range st {
			switch {
			case ok && en.finding[i] && !fixed[i]:
				fixes = append(fixes, i)
			case !ok && (en.base[i] || fixed[i]):
				breaks = append(breaks, i)
			}
		}
		return fixes, breaks
	}
	if wantOMF {
		fixes, breaks := try(false, true, nil)
		if len(breaks) == 0 {
			plan.OmitManagedFields = true
			for _, i := range fixes {
				fixed[i] = true
			}
		} else {
			for _, i := range omfTargets {
				plan.Open = append(plan.Open, Open{Finding: label(en.result(i)), Reason: "omitManagedFields would break " + en.names(breaks)})
			}
		}
	}
	for _, c := range cands {
		targets := en.labels(c.targets)
		if key(c.rule) == key(guardRule) {
			fixes, breaks := try(true, plan.OmitManagedFields, nil)
			if len(breaks) > 0 {
				plan.Rejected = append(plan.Rejected, Rejection{Rule: guardRule, Targets: targets, Breaks: en.labels(breaks)})
				continue
			}
			plan.Guard = true
			plan.GuardFixes = en.labels(fixes)
			for _, i := range fixes {
				fixed[i] = true
			}
			continue
		}
		needGuard := plan.Guard || c.rule.CouldMatchCredentials()
		rule := c.rule
		fixes, breaks := try(needGuard, plan.OmitManagedFields, &rule)
		switch {
		case len(breaks) > 0:
			plan.Rejected = append(plan.Rejected, Rejection{Rule: rule, Targets: targets, Breaks: en.labels(breaks)})
		case len(fixes) > 0:
			plan.Guard = needGuard
			for _, i := range fixes {
				fixed[i] = true
			}
			accepted = append(accepted, &Proposal{Rule: rule, Fixes: en.labels(fixes), Targets: targets})
		case en.unseen(c.targets):
			// Nothing in the log to simulate against, so only a rule that
			// cannot collide with another generated rule is safe to write.
			var clash *auditpolicy.Rule
			for _, o := range cands {
				if o != c && o.rule.Level != rule.Level && overlaps(o.rule, rule) {
					clash = &o.rule
					break
				}
			}
			if clash != nil {
				for _, i := range c.targets {
					plan.Open = append(plan.Open, Open{Finding: label(en.result(i)), Reason: "the current policy drops these requests, so the run could not see them, and the rule for them (" + describe(rule) + ") overlaps another generated rule (" + describe(*clash) + "); decide their order by hand"})
				}
				continue
			}
			plan.Guard = needGuard
			accepted = append(accepted, &Proposal{Rule: rule, Targets: targets, Unverified: true})
		default:
			for _, i := range c.targets {
				plan.Open = append(plan.Open, Open{Finding: label(en.result(i)), Reason: "raising or lowering the level of these requests does not change the result: " + firstError(en.result(i))})
			}
		}
	}
	accepted = merge(accepted)
	// A guard added for a rule accepted later could, in principle, have
	// changed an earlier verdict; the final simulation is the one reported.
	final := assemble(plan.Guard, accepted, nil)
	sim := simulate(in.Events, final, plan.OmitManagedFields)
	for i, ok := range en.statuses(sim) {
		if ok && en.finding[i] {
			plan.Fixed++
		}
	}
	plan.Accepted = accepted
	for i, isFinding := range en.finding {
		if isFinding && !fixed[i] && !en.targetedBy(i, accepted) && !en.reported(i, plan) {
			plan.Open = append(plan.Open, Open{Finding: label(en.result(i)), Reason: "no rule could be kept for it (see the rejected rules)"})
		}
	}

	before := budget.Compute(in.Env, in.Events, in.FetchedAt, in.Scenarios)
	var kept []*audit.Event
	for _, e := range sim {
		if e != nil {
			kept = append(kept, e)
		}
	}
	after := budget.Compute(in.Env, kept, in.FetchedAt, in.Scenarios)
	plan.IdleBefore = before.BytesPerDay(before.Background.Bytes)
	plan.IdleAfter = after.BytesPerDay(after.Background.Bytes)
	plan.IdleClean = before.Clean

	out, err := auditpolicy.Splice(original, plan.header(in.Env), plan.annotated(), plan.OmitManagedFields)
	if err != nil {
		return nil, err
	}
	plan.Output = out
	return plan, nil
}

func newEngine(in Input) *engine {
	en := &engine{in: in}
	logDescs := map[string]bool{}
	en.logRes = scenarios.LogChecks(in.Env, in.Events, in.Strict)
	for _, r := range en.logRes {
		logDescs[r.Expect.Desc] = true
	}
	for _, r := range in.Results {
		if r.Skipped != "" || r.Expect.Requirement == scenarios.ReqBudget || (r.Scenario == "global" && logDescs[r.Expect.Desc]) {
			continue
		}
		c := check{res: r, name: label(r)}
		m := r.Expect.Match
		m.Level = "" // the simulation changes levels; match on the rest
		for i, e := range in.Events {
			if m.Matches(e, in.Env.UserAgent) {
				c.matched = append(c.matched, i)
			}
		}
		en.checks = append(en.checks, c)
	}
	return en
}

// result returns the original result behind status index i.
func (en *engine) result(i int) *audit.Result {
	if i < len(en.checks) {
		return en.checks[i].res
	}
	return en.logRes[i-len(en.checks)]
}

// statuses re-verifies every check against a (simulated) log and reports
// which pass. The log checks can only get better under a simulation —
// bodies are removed, never invented — so they are re-run only when they
// failed to begin with.
func (en *engine) statuses(events []*audit.Event) []bool {
	out := make([]bool, 0, len(en.checks)+len(en.logRes))
	for _, c := range en.checks {
		var evs []*audit.Event
		for _, i := range c.matched {
			if events[i] != nil {
				evs = append(evs, events[i])
			}
		}
		r := audit.Verify(c.res.Scenario, c.res.Expect, evs, en.in.Env.UserAgent, en.in.Strict)
		out = append(out, passing(r))
	}
	var kept []*audit.Event
	for _, e := range events {
		if e != nil {
			kept = append(kept, e)
		}
	}
	for i, r := range en.logRes {
		if passing(r) {
			out = append(out, true)
			continue
		}
		out = append(out, passing(scenarios.LogChecks(en.in.Env, kept, en.in.Strict)[i]))
	}
	return out
}

// unseen reports whether the checks behind a candidate matched no event at
// all: the cluster's policy drops those requests, so no simulation can show
// what a rule for them would do.
func (en *engine) unseen(targets []int) bool {
	for _, i := range targets {
		if i >= len(en.checks) || len(en.checks[i].matched) > 0 {
			return false
		}
	}
	return len(targets) > 0
}

func (en *engine) targetedBy(i int, accepted []*Proposal) bool {
	name := label(en.result(i))
	for _, p := range accepted {
		if p.Unverified && audit.Contains(p.Targets, name) {
			return true
		}
	}
	return false
}

func (en *engine) reported(i int, plan *Plan) bool {
	name := label(en.result(i))
	for _, o := range plan.Open {
		if o.Finding == name {
			return true
		}
	}
	return false
}

func (en *engine) labels(idx []int) []string {
	var out []string
	for _, i := range idx {
		out = append(out, label(en.result(i)))
	}
	return out
}

func (en *engine) names(idx []int) string {
	l := en.labels(idx)
	if len(l) > 3 {
		return strings.Join(l[:3], "; ") + fmt.Sprintf(" and %d more", len(l)-3)
	}
	return strings.Join(l, "; ")
}

func firstError(r *audit.Result) string {
	if len(r.Errors) == 0 {
		return "no detail"
	}
	return r.Errors[0]
}

// before orders generated rules for first-match: the narrower rule first, so
// that each decides the requests it was derived for; among equally narrow
// rules, drops first, then the rules that lower a level, then those that
// raise it.
func before(a, b auditpolicy.Rule) bool {
	if sa, sb := specificity(a), specificity(b); sa != sb {
		return sa > sb
	}
	return order(a.Level) < order(b.Level)
}

// specificity scores how narrowly a rule selects requests.
func specificity(r auditpolicy.Rule) int {
	n := 0
	if len(r.Users) > 0 {
		n += 3
	}
	if len(r.UserGroups) > 0 {
		n += 2
	}
	if len(r.Namespaces) > 0 {
		n += 2
	}
	if len(r.Verbs) > 0 {
		n++
	}
	if len(r.NonResourceURLs) > 0 {
		n++
	}
	for _, gr := range r.Resources {
		if len(gr.ResourceNames) > 0 {
			n += 4
			break
		}
	}
	all := len(r.Resources) > 0
	for _, gr := range r.Resources {
		if len(gr.Resources) == 0 {
			all = false
		}
	}
	if all {
		n++
	}
	return n
}

// overlaps reports whether some request could match both rules. It errs on
// the side of yes: group membership, for one, cannot be known.
func overlaps(a, b auditpolicy.Rule) bool {
	disjoint := func(x, y []string) bool {
		if len(x) == 0 || len(y) == 0 {
			return false
		}
		for _, v := range x {
			if audit.Contains(y, v) {
				return false
			}
		}
		return true
	}
	if disjoint(a.Users, b.Users) || disjoint(a.Verbs, b.Verbs) || disjoint(a.Namespaces, b.Namespaces) {
		return false
	}
	resA := len(a.Resources) > 0 || len(a.Namespaces) > 0
	resB := len(b.Resources) > 0 || len(b.Namespaces) > 0
	if (resA && len(b.NonResourceURLs) > 0 && !resB) || (resB && len(a.NonResourceURLs) > 0 && !resA) {
		return false
	}
	if len(a.NonResourceURLs) > 0 && len(b.NonResourceURLs) > 0 {
		hit := false
		for _, x := range a.NonResourceURLs {
			for _, y := range b.NonResourceURLs {
				px, py := strings.TrimSuffix(x, "*"), strings.TrimSuffix(y, "*")
				if strings.HasPrefix(px, py) || strings.HasPrefix(py, px) {
					hit = true
				}
			}
		}
		if !hit {
			return false
		}
	}
	if len(a.Resources) > 0 && len(b.Resources) > 0 {
		for _, ga := range a.Resources {
			for _, gb := range b.Resources {
				if ga.Group == gb.Group && resourcesOverlap(ga.Resources, gb.Resources) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func resourcesOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	parts := func(s string) (string, string) {
		r, sub, _ := strings.Cut(s, "/")
		return r, sub
	}
	for _, x := range a {
		for _, y := range b {
			rx, sx := parts(x)
			ry, sy := parts(y)
			resOK := rx == ry || rx == "*" || ry == "*"
			subOK := sx == sy || sx == "*" || sy == "*" || (x == "*" || y == "*")
			if resOK && subOK {
				return true
			}
		}
	}
	return false
}

// order ranks levels: drops, then lowering, then raising.
func order(level string) int {
	switch level {
	case "None":
		return 0
	case "Metadata":
		return 1
	case "Request":
		return 2
	}
	return 3
}

// assemble puts the rules in the order they are written: the credential
// guard, then the accepted rules by level, then the rule under trial.
func assemble(guard bool, accepted []*Proposal, extra *auditpolicy.Rule) []auditpolicy.Rule {
	var rules []auditpolicy.Rule
	if guard {
		rules = append(rules, guardRule)
	}
	all := make([]auditpolicy.Rule, 0, len(accepted)+1)
	for _, p := range accepted {
		all = append(all, p.Rule)
	}
	if extra != nil {
		all = append(all, *extra)
	}
	sort.SliceStable(all, func(a, b int) bool { return before(all[a], all[b]) })
	return append(rules, all...)
}

// merge combines kept rules that differ only in their resources. Such rules
// sit in the same level class and give every request they match the same
// level, so their union decides exactly as they did one by one.
func merge(in []*Proposal) []*Proposal {
	shape := func(p *Proposal) string {
		r := p.Rule
		r.Resources = nil
		return key(r) + fmt.Sprint(p.Unverified)
	}
	var out []*Proposal
	byShape := map[string]*Proposal{}
	for _, p := range in {
		if len(p.Rule.Resources) == 0 {
			out = append(out, p)
			continue
		}
		k := shape(p)
		into := byShape[k]
		if into == nil {
			c := *p
			c.Rule.Resources = nil
			for _, gr := range p.Rule.Resources {
				gr.Resources = append([]string(nil), gr.Resources...)
				c.Rule.Resources = append(c.Rule.Resources, gr)
			}
			byShape[k] = &c
			out = append(out, &c)
			continue
		}
		for _, gr := range p.Rule.Resources {
			joined := false
			for i := range into.Rule.Resources {
				have := &into.Rule.Resources[i]
				if have.Group != gr.Group || strings.Join(have.ResourceNames, ",") != strings.Join(gr.ResourceNames, ",") {
					continue
				}
				if len(have.Resources) > 0 && len(gr.Resources) > 0 {
					for _, res := range gr.Resources {
						if !audit.Contains(have.Resources, res) {
							have.Resources = append(have.Resources, res)
						}
					}
				} else {
					have.Resources = nil // one of them already covers the whole group
				}
				joined = true
				break
			}
			if !joined {
				into.Rule.Resources = append(into.Rule.Resources, gr)
			}
		}
		into.Fixes = append(into.Fixes, p.Fixes...)
		into.Targets = append(into.Targets, p.Targets...)
	}
	return out
}

func key(r auditpolicy.Rule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// annotated renders the kept rules in their final order with the comments
// that say why each is there.
func (p *Plan) annotated() []auditpolicy.Annotated {
	var out []auditpolicy.Annotated
	if p.Guard {
		c := []string{"Credentials stay at Metadata whatever the rules below say: secret values,", "issued tokens and reviewed tokens live in these bodies."}
		out = append(out, auditpolicy.Annotated{Rule: guardRule, Comments: append(c, fixLines("fixes", p.GuardFixes)...)})
	}
	rules := assemble(false, p.Accepted, nil)
	for _, r := range rules {
		for _, a := range p.Accepted {
			if key(a.Rule) != key(r) {
				continue
			}
			var c []string
			if a.Unverified {
				c = append(c, "UNVERIFIED: the current policy drops these requests, so the run could not", "see them; check the effect on a test cluster first.")
				c = append(c, fixLines("for", a.Targets)...)
			} else {
				c = fixLines("fixes", a.Fixes)
			}
			out = append(out, auditpolicy.Annotated{Rule: r, Comments: c})
		}
	}
	return out
}

func fixLines(verb string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := []string{fmt.Sprintf("%s %d finding(s):", verb, len(names))}
	for i, n := range names {
		if i == 4 {
			out = append(out, fmt.Sprintf("  ... and %d more", len(names)-4))
			break
		}
		out = append(out, "  "+n)
	}
	return out
}

func (p *Plan) header(env *audit.Env) []string {
	h := []string{
		fmt.Sprintf("==== Added by k8-apt from run %s (%s) ====", env.RunID, env.Start.UTC().Format("2006-01-02")),
		"These rules come first, so they win under first-match; the rules of the",
		"original policy follow unchanged. Each was simulated against the events",
		fmt.Sprintf("of the run: together they fix %d of %d findings and break no passing check.", p.Fixed, p.Findings),
	}
	if n := len(p.Open); n > 0 {
		h = append(h, fmt.Sprintf("%d finding(s) stay open (not a matter of policy, or no safe rule); see the", n), "output of the run.")
	}
	return h
}

// Summary is the terminal report of the plan.
func (p *Plan) Summary(path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  POLICY GENERATOR\n")
	if p.AssumedBaseline {
		fmt.Fprintf(&b, "  extended policy/baseline.yaml (pass --policy with the policy the cluster runs)\n")
	}
	rules := len(p.Accepted)
	if p.Guard {
		rules++
	}
	unverified := 0
	for _, a := range p.Accepted {
		if a.Unverified {
			unverified++
		}
	}
	fmt.Fprintf(&b, "  wrote %s: %d rule(s) added", path, rules)
	if unverified > 0 {
		fmt.Fprintf(&b, " (%d unverified)", unverified)
	}
	if p.OmitManagedFields {
		fmt.Fprintf(&b, ", omitManagedFields: true")
	}
	fmt.Fprintf(&b, "\n  fixes %d of %d findings, breaks no passing check (simulated on this run's events)\n", p.Fixed, p.Findings)
	note := ""
	if !p.IdleClean {
		note = "  (indicative: no --idle-sample)"
	}
	fmt.Fprintf(&b, "  idle volume %s/day → %s/day%s\n", budget.MB(p.IdleBefore), budget.MB(p.IdleAfter), note)
	if len(p.Rejected) > 0 {
		fmt.Fprintf(&b, "\n  rejected rules (%d): each would turn passing checks into findings\n", len(p.Rejected))
		for _, r := range p.Rejected {
			fmt.Fprintf(&b, "  - %s\n      for:    %s\n      breaks: %s\n", describe(r.Rule), first(r.Targets), first(r.Breaks))
		}
	}
	if len(p.Open) > 0 {
		fmt.Fprintf(&b, "\n  still open (%d)\n", len(p.Open))
		for _, o := range p.Open {
			fmt.Fprintf(&b, "  - %s\n      %s\n", o.Finding, o.Reason)
		}
	}
	return b.String()
}

func first(l []string) string {
	if len(l) <= 1 {
		return strings.Join(l, "")
	}
	return fmt.Sprintf("%s (+%d more)", l[0], len(l)-1)
}

// describe is a one-line form of a rule for the terminal.
func describe(r auditpolicy.Rule) string {
	parts := []string{"level " + r.Level}
	if len(r.Users) > 0 {
		parts = append(parts, "users "+strings.Join(r.Users, ","))
	}
	if len(r.UserGroups) > 0 {
		parts = append(parts, "groups "+strings.Join(r.UserGroups, ","))
	}
	if len(r.Verbs) > 0 {
		parts = append(parts, "verbs "+strings.Join(r.Verbs, ","))
	}
	for _, gr := range r.Resources {
		g := gr.Group
		if g == "" {
			g = "core"
		}
		s := g
		if len(gr.Resources) > 0 {
			s += ":" + strings.Join(gr.Resources, ",")
		}
		parts = append(parts, s)
	}
	if len(r.Namespaces) > 0 {
		parts = append(parts, "ns "+strings.Join(r.Namespaces, ","))
	}
	if len(r.NonResourceURLs) > 0 {
		parts = append(parts, "urls "+strings.Join(r.NonResourceURLs, ","))
	}
	return strings.Join(parts, " · ")
}
