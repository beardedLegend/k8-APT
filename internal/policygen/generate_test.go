package policygen

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/auditpolicy"
	"github.com/beardedLegend/k8-apt/internal/config"
)

const ua = "k8-apt/testrun"

func testEnv() *audit.Env {
	return &audit.Env{
		Cfg: config.Default(), RunID: "testrun", UserAgent: ua,
		Namespace: "audit-test-testrun", AdminUser: "admin",
		Start: time.Now().Add(-time.Minute),
	}
}

// event builds a logged event; raw is filled so the budget can size it.
func event(user string, groups []string, verb, group, resource, ns, name, level string, body string) *audit.Event {
	e := &audit.Event{
		Level: level, Stage: "ResponseComplete", Verb: verb, UserAgent: ua,
		User:            audit.UserInfo{Username: user, Groups: groups},
		ObjectRef:       &audit.ObjectRef{APIGroup: group, Resource: resource, Namespace: ns, Name: name},
		ResponseStatus:  &audit.ResponseStatus{Code: 201},
		RequestReceived: time.Now(),
	}
	if body != "" {
		e.RequestObject = json.RawMessage(body)
	}
	raw, _ := json.Marshal(e)
	e.Raw = string(raw)
	return e
}

func results(events []*audit.Event, exs ...audit.Expect) []*audit.Result {
	var out []*audit.Result
	for _, ex := range exs {
		out = append(out, audit.Verify("s", ex, events, ua, false))
	}
	return out
}

func TestGenerateFixesRejectsAndExplains(t *testing.T) {
	env := testEnv()
	human := []string{"system:authenticated"}
	nodes := []string{"system:nodes", "system:authenticated"}
	events := []*audit.Event{
		// An RBAC write logged without body (the baseline's Metadata).
		event("admin", human, "create", "rbac.authorization.k8s.io", "clusterrolebindings", "", env.Name("pwn"), "Metadata", ""),
		// A kubelet reading a secret: must stay logged.
		event("system:node:n1", nodes, "get", "", "secrets", env.Namespace, "s", "Metadata", ""),
		// A kubelet reading a configmap: the noise a drop rule is after.
		event("system:node:n1", nodes, "get", "", "configmaps", env.Namespace, "c", "Metadata", ""),
		// A denied read by a kubelet identity that a passing check wants.
		event("system:node:n1", nodes, "list", "", "pods", env.Namespace, "", "RequestResponse", ""),
	}
	events[3].Annotations = map[string]string{"authorization.k8s.io/decision": "forbid"}
	events[3].ResponseStatus.Code = 403

	res := results(events,
		audit.Expect{
			Desc: "cluster-admin grant logged with body", Requirement: "R",
			Match: audit.Match{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Name: env.Name("pwn")},
			Level: "Request", RequestBody: audit.Required, Gap: "no body",
		},
		audit.Expect{
			Desc: "reads by system:nodes are dropped", Requirement: "R",
			Match: audit.Match{Verbs: []string{"get", "list", "watch"}, UserGroup: "system:nodes", NotResources: []string{"secrets"}, AnyUA: true},
			Level: "None", Gap: "noise",
		},
		audit.Expect{
			Desc: "denied pod list by a node identity is logged", Requirement: "R",
			Match: audit.Match{Verb: "list", Resource: "pods", UserGroup: "system:nodes", AnyUA: true},
			Level: "RequestResponse", Code: 403,
		},
		audit.Expect{
			Desc: "kubelet secret reads are logged", Requirement: "R",
			Match: audit.Match{Resource: "secrets", UserGroup: "system:nodes", AnyUA: true},
			Level: "Metadata",
		},
		audit.Expect{
			Desc: "the grant carries a decision annotation", Requirement: "R",
			Match:       audit.Match{Verb: "create", Resource: "clusterrolebindings"},
			Annotations: map[string]string{"authorization.k8s.io/decision": "allow"},
		},
	)

	plan, err := Generate(Input{Env: env, Events: events, Results: res, FetchedAt: time.Now(), Scenarios: 1}, Options{Fix: []string{"FAIL", "DIFF", "GAP"}})
	if err != nil {
		t.Fatal(err)
	}

	// The RBAC gap is fixed by a Request rule for writes to the group,
	// generalised away from the run's object name.
	if len(plan.Accepted) != 1 {
		t.Fatalf("accepted %d rules, want 1: %+v", len(plan.Accepted), plan.Accepted)
	}
	got := plan.Accepted[0].Rule
	if got.Level != "Request" || got.Resources[0].Group != "rbac.authorization.k8s.io" || len(got.Resources[0].ResourceNames) != 0 {
		t.Errorf("unexpected rule %+v", got)
	}
	if len(got.Users) != 0 {
		t.Errorf("the run's own identity leaked into the rule: %v", got.Users)
	}

	// Dropping all kubelet reads would hide the denied pod list: rejected.
	if len(plan.Rejected) != 1 || !strings.Contains(strings.Join(plan.Rejected[0].Breaks, " "), "denied pod list") {
		t.Errorf("want the node read drop rejected for breaking the denied-read check, got %+v", plan.Rejected)
	}

	// An annotation is not the policy's to decide.
	open := false
	for _, o := range plan.Open {
		if strings.Contains(o.Finding, "decision annotation") && strings.Contains(o.Reason, "annotations") {
			open = true
		}
	}
	if !open {
		t.Errorf("the annotation finding should be open with a reason: %+v", plan.Open)
	}

	// The output is a valid policy with the new rule first and the
	// original rules after it.
	p, err := auditpolicy.Parse(plan.Output)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Level != "Request" || p.Rules[0].Resources[0].Group != "rbac.authorization.k8s.io" {
		t.Errorf("first rule is %+v", p.Rules[0])
	}
	if !plan.AssumedBaseline || len(p.Rules) != 1+9 {
		t.Errorf("want the baseline's 9 rules after the new one, got %d rules", len(p.Rules))
	}
	if !strings.Contains(string(plan.Output), "s: cluster-admin grant logged with body") {
		t.Error("the rule is not annotated with the finding it fixes")
	}
}

func TestMergeIsAnExactUnion(t *testing.T) {
	rbac := "rbac.authorization.k8s.io"
	write := []string{"create"}
	a := &Proposal{Rule: auditpolicy.Rule{Level: "Request", Verbs: write, Resources: []auditpolicy.GroupResources{{Group: rbac, Resources: []string{"roles"}}}}, Fixes: []string{"a"}}
	b := &Proposal{Rule: auditpolicy.Rule{Level: "Request", Verbs: write, Resources: []auditpolicy.GroupResources{{Group: rbac, Resources: []string{"rolebindings"}}}}, Fixes: []string{"b"}}
	c := &Proposal{Rule: auditpolicy.Rule{Level: "Request", Verbs: []string{"update"}, Resources: []auditpolicy.GroupResources{{Group: rbac, Resources: []string{"roles"}}}}, Fixes: []string{"c"}}
	got := merge([]*Proposal{a, b, c})
	if len(got) != 2 {
		t.Fatalf("want the two create rules merged and the update rule kept apart, got %d rules", len(got))
	}
	if r := got[0].Rule.Resources[0].Resources; strings.Join(r, ",") != "roles,rolebindings" || len(got[0].Fixes) != 2 {
		t.Errorf("merged rule %+v fixes %v", got[0].Rule, got[0].Fixes)
	}
	if a.Rule.Resources[0].Resources[0] != "roles" || len(a.Rule.Resources[0].Resources) != 1 {
		t.Error("merge modified its input")
	}
}

func TestSimulateStripsAndPredicts(t *testing.T) {
	withMF := `{"metadata":{"name":"x","managedFields":[{"manager":"kubectl"}]},"spec":{}}`
	e := event("admin", nil, "create", "apps", "deployments", "ns", "x", "Request", withMF)
	down := simulate([]*audit.Event{e}, []auditpolicy.Rule{{Level: "Metadata"}}, false)[0]
	if len(down.RequestObject) != 0 || strings.Contains(down.Raw, "managedFields") {
		t.Errorf("Metadata must strip the body from the event and its raw line: %s", down.Raw)
	}
	if len(down.Raw) >= len(e.Raw) {
		t.Error("a stripped event must shrink for the budget")
	}
	kept := simulate([]*audit.Event{e}, nil, true)[0]
	if strings.Contains(string(kept.RequestObject), "managedFields") || !strings.Contains(string(kept.RequestObject), `"name":"x"`) {
		t.Errorf("omitManagedFields must remove only managedFields: %s", kept.RequestObject)
	}
	meta := event("admin", nil, "create", "apps", "deployments", "ns", "x", "Metadata", "")
	up := simulate([]*audit.Event{meta}, []auditpolicy.Rule{{Level: "Request"}}, false)[0]
	if !up.PredictedBody || len(up.RequestObject) == 0 {
		t.Error("raising a write to Request must predict a body")
	}
	if dropped := simulate([]*audit.Event{meta}, []auditpolicy.Rule{{Level: "None"}}, false)[0]; dropped != nil {
		t.Error("a None rule must drop the event")
	}
}

func TestOverlapAndOrder(t *testing.T) {
	cm := func(level string, ns ...string) auditpolicy.Rule {
		return auditpolicy.Rule{Level: level, Verbs: []string{"create"}, Namespaces: ns, Resources: []auditpolicy.GroupResources{{Group: "", Resources: []string{"configmaps"}}}}
	}
	general, kubeSystem := cm("Metadata"), cm("Request", "kube-system")
	if !overlaps(general, kubeSystem) {
		t.Error("a rule for all configmaps overlaps one for kube-system configmaps")
	}
	if !before(kubeSystem, general) || before(general, kubeSystem) {
		t.Error("the narrower rule must come first")
	}
	secrets := auditpolicy.Rule{Level: "Metadata", Verbs: []string{"create"}, Resources: []auditpolicy.GroupResources{{Group: "", Resources: []string{"secrets"}}}}
	if overlaps(general, secrets) {
		t.Error("configmaps and secrets do not overlap")
	}
	reads := auditpolicy.Rule{Level: "None", Verbs: []string{"get"}, UserGroups: []string{"system:nodes"}}
	if overlaps(reads, general) {
		t.Error("disjoint verbs do not overlap")
	}
	health := auditpolicy.Rule{Level: "None", NonResourceURLs: []string{"/healthz*"}}
	if overlaps(health, general) {
		t.Error("a non-resource rule does not overlap a resource rule")
	}
	if !resourcesOverlap([]string{"pods/*"}, []string{"pods/exec"}) || resourcesOverlap([]string{"pods/log"}, []string{"pods/exec"}) {
		t.Error("subresource patterns")
	}
}
