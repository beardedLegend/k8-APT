package policygen

import (
	"sort"
	"strings"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/auditpolicy"
)

// guardRule keeps credential bodies out of the log. It goes first whenever a
// generated rule could otherwise match secrets, token requests or token
// reviews: a rule that raises a level must never reach a secret, and a rule
// that drops component reads must not drop secret access with them.
var guardRule = auditpolicy.Rule{
	Level: "Metadata",
	Resources: []auditpolicy.GroupResources{
		{Group: "", Resources: []string{"secrets", "serviceaccounts/token"}},
		{Group: "authentication.k8s.io", Resources: []string{"tokenreviews"}},
	},
}

// derive turns one finding into the rule that would make its check pass,
// generalised so that it describes a kind of request rather than the objects
// of this run. It returns an empty reason on success, otherwise why no
// policy rule can fix the finding.
func derive(env *audit.Env, all []*audit.Event, r *audit.Result) (auditpolicy.Rule, string) {
	ex, m := r.Expect, r.Expect.Match
	var rule auditpolicy.Rule

	switch {
	case ex.Level != "":
		rule.Level = ex.Level
	case ex.RequestBody == audit.Required:
		rule.Level = "Request"
	case ex.MinEvents > 0:
		rule.Level = "Metadata"
	case ex.ResponseBody == audit.Forbidden && ex.RequestBody == "":
		rule.Level = "Request"
	case ex.RequestBody == audit.Forbidden:
		rule.Level = "Metadata"
	default:
		return rule, notALevel(ex)
	}

	if m.Verb != "" {
		rule.Verbs = []string{m.Verb}
	}
	rule.Verbs = append(rule.Verbs, m.Verbs...)

	testNS := func(ns string) bool {
		return ns == env.Namespace || (env.RunID != "" && strings.Contains(ns, env.RunID))
	}
	if u := m.User; u != "" {
		switch {
		case strings.HasPrefix(u, "system:serviceaccount:") && testNS(strings.Split(u, ":")[2]):
			// A service account the run created stands for any workload.
			rule.UserGroups = append(rule.UserGroups, "system:serviceaccounts")
		case u == env.AdminUser || (env.RunID != "" && strings.Contains(u, env.RunID)):
			// The run's own identity stands for any human.
		default:
			rule.Users = []string{u}
		}
	}
	if m.UserGroup != "" {
		rule.UserGroups = append(rule.UserGroups, m.UserGroup)
	}
	if p := m.UserPrefix; p != "" {
		if p == "system:serviceaccount:" {
			rule.UserGroups = append(rule.UserGroups, "system:serviceaccounts")
		} else {
			rule.Users = append(rule.Users, usersWithPrefix(all, p)...)
		}
	}

	if m.Namespace != "" && !testNS(m.Namespace) {
		rule.Namespaces = []string{m.Namespace}
	}

	if m.NonResource {
		switch {
		case m.URI != "":
			rule.NonResourceURLs = []string{m.URI}
		case m.URIPrefix != "":
			rule.NonResourceURLs = []string{m.URIPrefix + "*"}
		default:
			rule.NonResourceURLs = []string{"*"}
		}
	} else if gr := groupResources(all, r, m); len(gr) > 0 {
		// Only a drop is narrowed to object names: a narrow drop is safe,
		// a narrow "log more" is useless beyond this run.
		if rule.Level == "None" && m.Name != "" && !testNS(m.Namespace) && !strings.Contains(m.Name, env.RunID) {
			for i := range gr {
				gr[i].ResourceNames = []string{m.Name}
			}
		}
		rule.Resources = gr
	}

	if len(ex.Stages) > 0 && !audit.Contains(ex.Stages, "ResponseStarted") {
		rule.OmitStages = []string{"ResponseStarted"}
	}

	if len(rule.Users)+len(rule.UserGroups)+len(rule.Verbs)+len(rule.Resources)+len(rule.Namespaces)+len(rule.NonResourceURLs) == 0 {
		return rule, "the check covers every request; a rule for it would override the whole policy"
	}
	return rule, ""
}

// notALevel explains a finding that is not about what the policy records.
func notALevel(ex audit.Expect) string {
	switch {
	case ex.Code != 0:
		return "the check is about the response code, which the API server decides, not the audit policy"
	case len(ex.Annotations) > 0 || len(ex.AnnotationsPresent) > 0 || len(ex.AnnotationsAbsent) > 0:
		return "the check is about annotations, which authorization and admission write, not the audit policy"
	case ex.Impersonated != "" || len(ex.ImpersonatedGroups) > 0 || ex.NoImpersonation || ex.ImpersonatedUID != "":
		return "the check is about the recorded identity, which the audit policy does not change"
	case len(ex.Stages) > 0:
		return "the check is about stages the policy already records"
	}
	return "the check is not about the audit level"
}

// groupResources maps the resource part of a matcher onto policy resources.
func groupResources(all []*audit.Event, r *audit.Result, m audit.Match) []auditpolicy.GroupResources {
	var names []string
	res := m.Resources
	if m.Resource != "" {
		res = append([]string{m.Resource}, res...)
	}
	for _, x := range res {
		switch m.Subresource {
		case "-":
			names = append(names, x)
		case "":
			names = append(names, x, x+"/*")
		default:
			names = append(names, x+"/"+m.Subresource)
		}
	}
	if len(res) == 0 && m.Subresource != "" && m.Subresource != "-" {
		names = []string{"*/" + m.Subresource}
	}

	var groups []string
	switch {
	case m.Group != "":
		groups = []string{m.Group}
	case len(m.Groups) > 0:
		groups = m.Groups
	case len(res) > 0:
		groups = groupsOf(r.Events, res)
		if len(groups) == 0 {
			groups = groupsOf(all, res)
		}
		if len(groups) == 0 {
			groups = []string{"core"}
		}
	case len(names) > 0:
		groups = groupsOf(r.Events, nil)
	}
	var out []auditpolicy.GroupResources
	for _, g := range groups {
		if g == "core" {
			g = ""
		}
		out = append(out, auditpolicy.GroupResources{Group: g, Resources: append([]string(nil), names...)})
	}
	return out
}

// groupsOf lists the API groups the events address, restricted to the named
// resources when given.
func groupsOf(events []*audit.Event, resources []string) []string {
	seen := map[string]bool{}
	for _, e := range events {
		if e.ObjectRef == nil || e.Resource() == "" {
			continue
		}
		if len(resources) > 0 && !audit.Contains(resources, e.Resource()) {
			continue
		}
		seen[audit.GroupKey(e.Group())] = true
	}
	var out []string
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// usersWithPrefix lists the usernames in the log that start with prefix, so
// that a matcher on "system:kube-" becomes the component users it meant.
func usersWithPrefix(events []*audit.Event, prefix string) []string {
	seen := map[string]bool{}
	for _, e := range events {
		if strings.HasPrefix(e.User.Username, prefix) {
			seen[e.User.Username] = true
		}
	}
	var out []string
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}
