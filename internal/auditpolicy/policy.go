// Package auditpolicy models an audit.k8s.io/v1 Policy: parsing it, deciding
// which rule an audit event falls under (with the API server's first-match
// semantics), rendering rules as YAML and splicing new rules into an existing
// policy file without losing its comments.
package auditpolicy

import (
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

// Policy is the subset of audit.k8s.io/v1 Policy that decides levels.
type Policy struct {
	APIVersion        string   `json:"apiVersion"`
	Kind              string   `json:"kind"`
	OmitStages        []string `json:"omitStages,omitempty"`
	OmitManagedFields bool     `json:"omitManagedFields,omitempty"`
	Rules             []Rule   `json:"rules"`
}

// Rule is one audit.k8s.io/v1 PolicyRule. Empty lists are wildcards.
type Rule struct {
	Level             string           `json:"level"`
	Users             []string         `json:"users,omitempty"`
	UserGroups        []string         `json:"userGroups,omitempty"`
	Verbs             []string         `json:"verbs,omitempty"`
	Resources         []GroupResources `json:"resources,omitempty"`
	Namespaces        []string         `json:"namespaces,omitempty"`
	NonResourceURLs   []string         `json:"nonResourceURLs,omitempty"`
	OmitStages        []string         `json:"omitStages,omitempty"`
	OmitManagedFields *bool            `json:"omitManagedFields,omitempty"`
}

// GroupResources selects resources of one API group ("" is core).
type GroupResources struct {
	Group         string   `json:"group"`
	Resources     []string `json:"resources,omitempty"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// Parse reads a policy file.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	if err := yaml.UnmarshalStrict(raw, &p); err != nil {
		return nil, err
	}
	if p.Kind != "Policy" {
		return nil, fmt.Errorf("kind %q, want Policy", p.Kind)
	}
	for i, r := range p.Rules {
		switch r.Level {
		case "None", "Metadata", "Request", "RequestResponse":
		default:
			return nil, fmt.Errorf("rule %d: unknown level %q", i+1, r.Level)
		}
	}
	return &p, nil
}

// Levels in increasing order of detail.
var levelRank = map[string]int{"None": 0, "Metadata": 1, "Request": 2, "RequestResponse": 3}

// Rank orders audit levels: None < Metadata < Request < RequestResponse.
func Rank(level string) int { return levelRank[level] }

// First returns the index of the first rule that matches e, or -1.
func First(rules []Rule, e *audit.Event) int {
	for i := range rules {
		if rules[i].Matches(e) {
			return i
		}
	}
	return -1
}

// Matches reports whether the rule applies to the request behind e, with
// the semantics of the API server's policy checker: the policy is matched
// against the authenticated user (not the impersonated one), a rule with
// resources or namespaces matches only resource requests, a rule with
// nonResourceURLs only non-resource requests.
func (r *Rule) Matches(e *audit.Event) bool {
	if len(r.Users) > 0 && !audit.Contains(r.Users, e.User.Username) {
		return false
	}
	if len(r.UserGroups) > 0 {
		in := false
		for _, g := range e.User.Groups {
			if audit.Contains(r.UserGroups, g) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	if len(r.Verbs) > 0 && !audit.Contains(r.Verbs, e.Verb) {
		return false
	}
	isResource := e.ObjectRef != nil && e.ObjectRef.Resource != ""
	if len(r.Namespaces) > 0 || len(r.Resources) > 0 {
		return isResource && r.matchesResource(e)
	}
	if len(r.NonResourceURLs) > 0 {
		return !isResource && r.matchesNonResource(e)
	}
	return true
}

func (r *Rule) matchesResource(e *audit.Event) bool {
	if len(r.Namespaces) > 0 && !audit.Contains(r.Namespaces, e.Namespace()) {
		return false
	}
	if len(r.Resources) == 0 {
		return true
	}
	res, sub, name := e.Resource(), e.Subresource(), e.Name()
	combined := res
	if sub != "" {
		combined = res + "/" + sub
	}
	for _, gr := range r.Resources {
		if gr.Group != e.Group() {
			continue
		}
		if len(gr.Resources) == 0 {
			return true
		}
		if len(gr.ResourceNames) > 0 && !audit.Contains(gr.ResourceNames, name) {
			continue
		}
		for _, want := range gr.Resources {
			switch {
			case want == combined, want == "*":
				return true
			case sub != "" && strings.HasPrefix(want, "*/") && sub == strings.TrimPrefix(want, "*/"):
				return true
			// Like the API server, "resource/*" matches the resource itself
			// as well as its subresources.
			case strings.HasSuffix(want, "/*") && res == strings.TrimSuffix(want, "/*"):
				return true
			}
		}
	}
	return false
}

func (r *Rule) matchesNonResource(e *audit.Event) bool {
	path := strings.SplitN(e.RequestURI, "?", 2)[0]
	for _, u := range r.NonResourceURLs {
		if u == "*" || u == path || (strings.HasSuffix(u, "*") && strings.HasPrefix(path, strings.TrimSuffix(u, "*"))) {
			return true
		}
	}
	return false
}

// CouldMatchCredentials reports whether the rule could apply to requests for
// secrets, service account tokens or token reviews — the resources whose
// bodies carry credentials.
func (r *Rule) CouldMatchCredentials() bool {
	if len(r.NonResourceURLs) > 0 && len(r.Resources) == 0 && len(r.Namespaces) == 0 {
		return false
	}
	if len(r.Resources) == 0 {
		return true
	}
	for _, gr := range r.Resources {
		switch gr.Group {
		case "":
			if len(gr.Resources) == 0 {
				return true
			}
			for _, res := range gr.Resources {
				if res == "*" || res == "secrets" || res == "serviceaccounts/token" || res == "*/token" || res == "serviceaccounts/*" {
					return true
				}
			}
		case "authentication.k8s.io":
			return true
		}
	}
	return false
}
