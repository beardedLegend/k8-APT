package scenarios

import (
	"strings"
	"testing"

	"github.com/your-org/k8-apt/internal/audit"
	"github.com/your-org/k8-apt/internal/config"
)

// envFor builds the Env a scenario's Expect closure needs, without a cluster.
func envFor(cfg *config.Cluster) *audit.Env {
	return &audit.Env{
		Cfg:         cfg,
		RunID:       "testrun",
		UserAgent:   "k8-apt/testrun",
		Namespace:   cfg.NamespacePrefix + "-testrun",
		AdminUser:   "test-admin",
		Domain:      cfg.TestDomain,
		Image:       cfg.Image,
		ProxySA:     cfg.Component.Proxy.ProxySA(),
		ProxyUser:   "user@example.test",
		ProxyGroups: []string{"group"},
		WorkerNode:  "node-1",
		RogueNode:   "node-1",
	}
}

func TestScenarioNamesAreUniqueAndValid(t *testing.T) {
	env := envFor(config.Default())
	seen := map[string]bool{}
	for _, s := range Scenarios(env) {
		if s.Name == "" {
			t.Error("a scenario has no name")
		}
		if seen[s.Name] {
			t.Errorf("duplicate scenario name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Act == nil {
			t.Errorf("%s: no Act", s.Name)
		}
		if s.Expect == nil {
			t.Errorf("%s: no Expect", s.Name)
		}
		if strings.ToLower(s.Name) != s.Name {
			t.Errorf("%s: scenario names are lowercase", s.Name)
		}
	}
	if len(seen) < 50 {
		t.Errorf("only %d scenarios; expected the full set", len(seen))
	}
}

// TestExpectationsAreWellFormed builds every expectation of every scenario
// and checks the fields the report relies on. It catches a scenario that was
// added without a requirement, a description or a usable matcher.
func TestExpectationsAreWellFormed(t *testing.T) {
	cfg := config.Default()
	cfg.Component.Proxy = config.ProxyComponent{
		Enabled:                 true,
		ServiceAccountNamespace: "proxy-ns",
		ServiceAccountName:      "proxy-sa",
	}
	cfg.Component.Calico.Enabled = true
	env := envFor(cfg)

	known := map[string]bool{}
	for _, r := range RequirementOrder {
		known[r] = true
	}
	n := 0
	for _, s := range Scenarios(env) {
		for _, ex := range s.Expect(env) {
			n++
			switch {
			case ex.Desc == "":
				t.Errorf("%s: an expectation has no description", s.Name)
			case ex.Requirement == "":
				t.Errorf("%s/%s: no requirement", s.Name, ex.Desc)
			case !known[ex.Requirement]:
				t.Errorf("%s/%s: requirement %q is not in RequirementOrder", s.Name, ex.Desc, ex.Requirement)
			}
			if ex.Match.String() == "" {
				t.Errorf("%s/%s: empty matcher would match every event", s.Name, ex.Desc)
			}
			if ex.Level == "" && ex.RequestBody == "" && ex.ResponseBody == "" &&
				ex.Code == 0 && len(ex.Stages) == 0 && len(ex.Annotations) == 0 &&
				ex.Impersonated == "" && len(ex.ImpersonatedGroups) == 0 &&
				!ex.UsernameEmpty && !ex.NoImpersonation && ex.MinEvents == 0 &&
				len(ex.RequestBodyContains) == 0 && len(ex.AnnotationsAbsent) == 0 {
				t.Errorf("%s/%s: expectation asserts nothing", s.Name, ex.Desc)
			}
			if ex.Tier != "" && ex.Tier != audit.Invariant && ex.Tier != audit.Baseline {
				t.Errorf("%s/%s: unknown tier %q", s.Name, ex.Desc, ex.Tier)
			}
		}
	}
	for _, ex := range GlobalExpectations(env) {
		n++
		if ex.Desc == "" || ex.Requirement == "" {
			t.Errorf("a global expectation is missing a description or requirement: %+v", ex)
		}
	}
	if n < 250 {
		t.Errorf("only %d expectations were built; expected the full set", n)
	}
	t.Logf("%d expectations over %d scenarios", n, len(Scenarios(env)))
}

// TestComponentsGateScenarios checks that the optional components really do
// add and remove scenarios, so a stock cluster is not asked for Calico.
func TestComponentsGateScenarios(t *testing.T) {
	plain := len(Scenarios(envFor(config.Default())))

	cfg := config.Default()
	cfg.Component.Calico.Enabled = true
	cfg.Component.Proxy = config.ProxyComponent{
		Enabled:                 true,
		ServiceAccountNamespace: "proxy-ns",
		ServiceAccountName:      "proxy-sa",
	}
	full := len(Scenarios(envFor(cfg)))
	if full <= plain {
		t.Errorf("enabling components did not add scenarios: %d vs %d", full, plain)
	}
	for _, s := range Scenarios(envFor(config.Default())) {
		if strings.HasPrefix(s.Name, "calico") || strings.HasPrefix(s.Name, "authproxy-") {
			t.Errorf("%s runs although its component is disabled", s.Name)
		}
	}
}

// TestTestDomainIsConfigurable checks that the suite really uses the domain
// from the profile: no expectation may carry the default domain when another
// one is configured, and the configured one must actually turn up.
func TestTestDomainIsConfigurable(t *testing.T) {
	const custom = "audit.probe.invalid"
	cfg := config.Default()
	cfg.TestDomain = custom
	env := envFor(cfg)
	used := false
	for _, s := range Scenarios(env) {
		for _, ex := range s.Expect(env) {
			hay := ex.Desc + " " + ex.Match.String() + " " +
				strings.Join(ex.RequestBodyContains, " ")
			if strings.Contains(hay, config.Default().TestDomain) {
				t.Errorf("%s/%s: the default test domain is hard-coded in %q", s.Name, ex.Desc, hay)
			}
			if strings.Contains(hay, custom) {
				used = true
			}
		}
	}
	if !used {
		t.Error("no expectation used the configured test domain")
	}
}
