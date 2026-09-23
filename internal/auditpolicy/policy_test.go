package auditpolicy

import (
	"strings"
	"testing"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/policy"
)

func resEvent(user string, groups []string, verb, group, resource, sub, ns, name string) *audit.Event {
	return &audit.Event{
		Verb: verb,
		User: audit.UserInfo{Username: user, Groups: groups},
		ObjectRef: &audit.ObjectRef{
			APIGroup: group, Resource: resource, Subresource: sub, Namespace: ns, Name: name,
		},
	}
}

func levelOf(t *testing.T, p *Policy, e *audit.Event) string {
	t.Helper()
	i := First(p.Rules, e)
	if i < 0 {
		return "None"
	}
	return p.Rules[i].Level
}

// TestBaselineLevels pins the evaluator to the documented behaviour of the
// Kubernetes documentation example, rule by rule.
func TestBaselineLevels(t *testing.T) {
	p, err := Parse(policy.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	human := []string{"system:authenticated"}
	anon := []string{"system:unauthenticated"}
	for _, c := range []struct {
		name string
		ev   *audit.Event
		want string
	}{
		{"pod create", resEvent("alice", human, "create", "", "pods", "", "app", "p"), "RequestResponse"},
		{"pod exec is a subresource, not pods", resEvent("alice", human, "create", "", "pods", "exec", "app", "p"), "Request"},
		{"pod log", resEvent("alice", human, "get", "", "pods", "log", "app", "p"), "Metadata"},
		{"pod status", resEvent("kubelet", []string{"system:nodes"}, "patch", "", "pods", "status", "app", "p"), "Metadata"},
		{"controller-leader configmap", resEvent("x", human, "update", "", "configmaps", "", "any", "controller-leader"), "None"},
		{"kube-proxy watch", resEvent("system:kube-proxy", human, "watch", "", "endpoints", "", "", ""), "None"},
		{"kube-proxy get is not dropped", resEvent("system:kube-proxy", human, "get", "", "endpoints", "", "", ""), "Request"},
		{"kube-system configmap read", resEvent("alice", human, "get", "", "configmaps", "", "kube-system", "coredns"), "Request"},
		{"other configmap", resEvent("alice", human, "create", "", "configmaps", "", "app", "c"), "Metadata"},
		{"secret", resEvent("alice", human, "get", "", "secrets", "", "kube-system", "s"), "Metadata"},
		{"token request", resEvent("alice", human, "create", "", "serviceaccounts", "token", "app", "sa"), "Request"},
		{"node", resEvent("alice", human, "patch", "", "nodes", "", "", "n1"), "Request"},
		{"extensions group", resEvent("alice", human, "get", "extensions", "ingresses", "", "app", "i"), "Request"},
		{"apps group", resEvent("alice", human, "create", "apps", "deployments", "", "app", "d"), "Metadata"},
		{"rbac group", resEvent("alice", human, "create", "rbac.authorization.k8s.io", "clusterrolebindings", "", "", "b"), "Metadata"},
	} {
		if got := levelOf(t, p, c.ev); got != c.want {
			t.Errorf("%s: level %s, want %s", c.name, got, c.want)
		}
	}

	nr := func(user string, groups []string, uri string) *audit.Event {
		return &audit.Event{Verb: "get", RequestURI: uri, User: audit.UserInfo{Username: user, Groups: groups}}
	}
	for _, c := range []struct {
		name string
		ev   *audit.Event
		want string
	}{
		{"authenticated discovery", nr("alice", human, "/apis/apps/v1?timeout=32s"), "None"},
		{"authenticated /version", nr("alice", human, "/version"), "None"},
		{"authenticated /healthz", nr("alice", human, "/healthz"), "Metadata"},
		{"anonymous discovery", nr("system:anonymous", anon, "/api"), "Metadata"},
	} {
		if got := levelOf(t, p, c.ev); got != c.want {
			t.Errorf("%s: level %s, want %s", c.name, got, c.want)
		}
	}
}

func TestResourcePatterns(t *testing.T) {
	r := Rule{Level: "Request", Resources: []GroupResources{{Group: "", Resources: []string{"pods/*", "*/scale"}}}}
	for _, c := range []struct {
		res, sub string
		want     bool
	}{
		{"pods", "exec", true},
		// The API server compares only the resource for "resource/*", so it
		// matches the resource itself as well.
		{"pods", "", true},
		{"deployments", "scale", true},
		{"services", "proxy", false},
	} {
		if got := r.Matches(resEvent("u", nil, "get", "", c.res, c.sub, "ns", "x")); got != c.want {
			t.Errorf("%s/%s: %v, want %v", c.res, c.sub, got, c.want)
		}
	}
	nonres := Rule{Level: "None", NonResourceURLs: []string{"/healthz*"}}
	if nonres.Matches(resEvent("u", nil, "get", "", "pods", "", "", "")) {
		t.Error("a nonResourceURLs rule matched a resource request")
	}
}

func TestSplice(t *testing.T) {
	add := []Annotated{{
		Rule:     Rule{Level: "Request", Verbs: []string{"create"}, Resources: []GroupResources{{Group: "rbac.authorization.k8s.io"}}},
		Comments: []string{"fixes 1 finding(s):"},
	}}
	out, err := Splice(policy.Baseline, []string{"added by a test"}, add, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Level != "Request" || p.Rules[0].Resources[0].Group != "rbac.authorization.k8s.io" {
		t.Errorf("the new rule is not first: %+v", p.Rules[0])
	}
	if !p.OmitManagedFields {
		t.Error("omitManagedFields was not set")
	}
	s := string(out)
	for _, keep := range []string{"# Log pod changes at RequestResponse level", "# added by a test", "# ---- the original rules follow"} {
		if !strings.Contains(s, keep) {
			t.Errorf("output lacks %q", keep)
		}
	}
}
