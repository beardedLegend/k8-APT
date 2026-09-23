package compliance

import (
	"testing"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/scenarios"
)

// Every control rests on requirements the run knows, and every requirement
// is evidence for at least one control.
func TestMapping(t *testing.T) {
	used := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range Controls {
		key := c.Framework.Short + " " + c.ID
		if seen[key] {
			t.Errorf("%s is listed twice", key)
		}
		seen[key] = true
		if len(c.Reqs) == 0 && c.Beyond == "" {
			t.Errorf("%s has neither requirements nor a Beyond note", key)
		}
		for _, r := range c.Reqs {
			if !audit.Contains(scenarios.RequirementOrder, r) {
				t.Errorf("%s: unknown requirement %q", key, r)
			}
			used[r] = true
		}
	}
	for _, r := range scenarios.RequirementOrder {
		if !used[r] {
			t.Errorf("requirement %q maps to no control", r)
		}
	}
}

func TestAssess(t *testing.T) {
	res := func(req, gap string, errs ...string) *audit.Result {
		return &audit.Result{Expect: audit.Expect{Requirement: req, Gap: gap, Tier: audit.Invariant}, Errors: errs}
	}
	as := Assess([]*audit.Result{
		res(scenarios.ReqResources, "no body", "missing"),
		res(scenarios.ReqRBAC, ""),
		res(scenarios.ReqExec, "", "missing"),
	})
	want := map[string]string{
		"A.5.18": Met,       // R02 only
		"A.8.9":  Gap,       // R01 gapped, R17 absent
		"A.8.2":  Fail,      // R03 failed
		"A.8.17": Elsewhere, // nothing testable
		"A.8.3":  NotTested, // R09 absent
	}
	for _, a := range as {
		if w, ok := want[a.ID]; ok && a.Framework == ISO27001 && a.Status != w {
			t.Errorf("%s: status %s, want %s (%v)", a.ID, a.Status, w, a.Findings)
		}
	}
}
