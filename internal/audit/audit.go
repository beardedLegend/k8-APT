// Package audit holds the model of an audit event, the matcher and
// expectation language the scenarios are written in, and the verifier that
// checks a set of expectations against the events a run produced.
package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Audit event model (subset of audit.k8s.io/v1 Event, plus the raw line)
// ---------------------------------------------------------------------------

type Event struct {
	Level            string            `json:"level"`
	AuditID          string            `json:"auditID"`
	Stage            string            `json:"stage"`
	RequestURI       string            `json:"requestURI"`
	Verb             string            `json:"verb"`
	User             UserInfo          `json:"user"`
	ImpersonatedUser *UserInfo         `json:"impersonatedUser,omitempty"`
	SourceIPs        []string          `json:"sourceIPs"`
	UserAgent        string            `json:"userAgent"`
	ObjectRef        *ObjectRef        `json:"objectRef,omitempty"`
	ResponseStatus   *ResponseStatus   `json:"responseStatus,omitempty"`
	RequestObject    json.RawMessage   `json:"requestObject,omitempty"`
	ResponseObject   json.RawMessage   `json:"responseObject,omitempty"`
	RequestReceived  time.Time         `json:"requestReceivedTimestamp"`
	StageTimestamp   time.Time         `json:"stageTimestamp"`
	Annotations      map[string]string `json:"annotations"`
	Raw              string            `json:"-"`
	Host             string            `json:"-"`
	// PredictedBody marks an event of a policy simulation whose request body
	// the policy would record but the log never did: the body is a
	// placeholder, so checks of its content are taken as satisfied.
	PredictedBody bool `json:"-"`
}

type UserInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type ObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
	Subresource string `json:"subresource"`
}

type ResponseStatus struct {
	Code int `json:"code"`
}

func (e *Event) Resource() string {
	if e.ObjectRef == nil {
		return ""
	}
	return e.ObjectRef.Resource
}

func (e *Event) Subresource() string {
	if e.ObjectRef == nil {
		return ""
	}
	return e.ObjectRef.Subresource
}

func (e *Event) Group() string {
	if e.ObjectRef == nil {
		return ""
	}
	return e.ObjectRef.APIGroup
}

func (e *Event) Namespace() string {
	if e.ObjectRef == nil {
		return ""
	}
	return e.ObjectRef.Namespace
}

func (e *Event) Name() string {
	if e.ObjectRef == nil {
		return ""
	}
	return e.ObjectRef.Name
}

func (e *Event) HasGroup(g string) bool {
	for _, x := range e.User.Groups {
		if x == g {
			return true
		}
	}
	return false
}

func (e *Event) ImpersonatedGroupHas(g string) bool {
	if e.ImpersonatedUser == nil {
		return false
	}
	for _, x := range e.ImpersonatedUser.Groups {
		if x == g {
			return true
		}
	}
	return false
}

func (e *Event) Short() string {
	who := e.User.Username
	if e.ImpersonatedUser != nil {
		who += " as " + e.ImpersonatedUser.Username
	}
	code := 0
	if e.ResponseStatus != nil {
		code = e.ResponseStatus.Code
	}
	body := ""
	if len(e.RequestObject) > 0 {
		body += " +req"
	}
	if len(e.ResponseObject) > 0 {
		body += " +resp"
	}
	return fmt.Sprintf("[%s %-15s %-6s %3d %s%s] %s %s", e.Host, e.Level, e.Stage, code, who, body, e.Verb, e.RequestURI)
}

// ---------------------------------------------------------------------------
// Matchers and expectations
// ---------------------------------------------------------------------------

// Match selects events. Empty fields are wildcards. By default only events
// carrying this run's User-Agent are considered, so that events of other
// clients and of previous runs never interfere; set AnyUA for events caused
// indirectly (controllers, kubelets, ...).
type Match struct {
	Verb         string
	Verbs        []string
	Group        string   // "core" for the empty group
	Groups       []string // any of ("core" for the empty group)
	NotGroups    []string // none of
	Resource     string
	Resources    []string // any of
	NotResources []string // none of
	Subresource  string   // "-" for "no subresource"
	Namespace    string
	Name         string
	NamePrefix   string
	User         string
	NotUser      string // exclude this exact username
	UserPrefix   string
	UserGroup    string
	URI          string // exact requestURI
	URIPrefix    string
	URIContains  string
	Stage        string
	Level        string // audit level of the event ("" = any)
	AnyUA        bool
	NonResource  bool // objectRef must be absent
	// ImpersonatedUser selects events where that user was impersonated.
	ImpersonatedUser string
	// ImpersonatedGroup selects events whose impersonatedUser is in that group.
	ImpersonatedGroup string
	// ResponseCode selects events with that HTTP status (0 = any).
	ResponseCode int
}

func (m Match) Matches(e *Event, runUA string) bool {
	if !m.AnyUA && e.UserAgent != runUA {
		return false
	}
	if m.Verb != "" && e.Verb != m.Verb {
		return false
	}
	if len(m.Verbs) > 0 && !Contains(m.Verbs, e.Verb) {
		return false
	}
	if m.NonResource && e.ObjectRef != nil && e.ObjectRef.Resource != "" {
		return false
	}
	if m.Group != "" {
		g := e.Group()
		if m.Group == "core" {
			if g != "" {
				return false
			}
		} else if g != m.Group {
			return false
		}
	}
	if len(m.Groups) > 0 && !Contains(m.Groups, GroupKey(e.Group())) {
		return false
	}
	if len(m.NotGroups) > 0 && Contains(m.NotGroups, GroupKey(e.Group())) {
		return false
	}
	if m.Resource != "" && e.Resource() != m.Resource {
		return false
	}
	if len(m.Resources) > 0 && !Contains(m.Resources, e.Resource()) {
		return false
	}
	if len(m.NotResources) > 0 && Contains(m.NotResources, e.Resource()) {
		return false
	}
	if m.URI != "" && e.RequestURI != m.URI {
		return false
	}
	if m.Subresource == "-" {
		if e.Subresource() != "" {
			return false
		}
	} else if m.Subresource != "" && e.Subresource() != m.Subresource {
		return false
	}
	if m.Namespace != "" && e.Namespace() != m.Namespace {
		return false
	}
	if m.Name != "" && e.Name() != m.Name {
		return false
	}
	if m.NamePrefix != "" && !strings.HasPrefix(e.Name(), m.NamePrefix) {
		return false
	}
	if m.User != "" && e.User.Username != m.User {
		return false
	}
	if m.NotUser != "" && e.User.Username == m.NotUser {
		return false
	}
	if m.UserPrefix != "" && !strings.HasPrefix(e.User.Username, m.UserPrefix) {
		return false
	}
	if m.UserGroup != "" && !e.HasGroup(m.UserGroup) {
		return false
	}
	if m.URIPrefix != "" && !strings.HasPrefix(e.RequestURI, m.URIPrefix) {
		return false
	}
	if m.URIContains != "" && !strings.Contains(e.RequestURI, m.URIContains) {
		return false
	}
	if m.Stage != "" && e.Stage != m.Stage {
		return false
	}
	if m.Level != "" && e.Level != m.Level {
		return false
	}
	if m.ImpersonatedUser != "" && (e.ImpersonatedUser == nil || e.ImpersonatedUser.Username != m.ImpersonatedUser) {
		return false
	}
	if m.ImpersonatedGroup != "" && !e.ImpersonatedGroupHas(m.ImpersonatedGroup) {
		return false
	}
	if m.ResponseCode != 0 && (e.ResponseStatus == nil || e.ResponseStatus.Code != m.ResponseCode) {
		return false
	}
	return true
}

func (m Match) String() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("verb", m.Verb)
	if len(m.Verbs) > 0 {
		add("verbs", strings.Join(m.Verbs, "|"))
	}
	add("group", m.Group)
	if len(m.Groups) > 0 {
		add("groups", strings.Join(m.Groups, "|"))
	}
	if len(m.NotGroups) > 0 {
		add("notGroups", strings.Join(m.NotGroups, "|"))
	}
	add("resource", m.Resource)
	if len(m.Resources) > 0 {
		add("resources", strings.Join(m.Resources, "|"))
	}
	if len(m.NotResources) > 0 {
		add("notResources", strings.Join(m.NotResources, "|"))
	}
	add("uri", m.URI)
	add("subresource", m.Subresource)
	add("ns", m.Namespace)
	add("name", m.Name)
	add("namePrefix", m.NamePrefix)
	add("user", m.User)
	add("notUser", m.NotUser)
	add("userPrefix", m.UserPrefix)
	add("userGroup", m.UserGroup)
	add("uriPrefix", m.URIPrefix)
	add("uriContains", m.URIContains)
	add("stage", m.Stage)
	add("level", m.Level)
	add("impersonated", m.ImpersonatedUser)
	add("impersonatedGroup", m.ImpersonatedGroup)
	if m.ResponseCode != 0 {
		add("code", strconv.Itoa(m.ResponseCode))
	}
	if m.NonResource {
		parts = append(parts, "nonResource")
	}
	if m.AnyUA {
		parts = append(parts, "anyUA")
	}
	return strings.Join(parts, " ")
}

// Expect describes what the audit log must contain for one action.
type Expect struct {
	Desc  string
	Match Match
	// Level is the expected audit level of every matched event, or "None" if
	// no event may exist.
	Level string
	// Stages, if set, is the exact set of stages that must be present.
	Stages []string
	// RequestBody / ResponseBody: "required", "forbidden" or "" (don't care).
	RequestBody  string
	ResponseBody string
	// RequestBodyContains are substrings that must appear in requestObject.
	RequestBodyContains []string
	// RequestBodyLacks are substrings that must not appear in requestObject.
	RequestBodyLacks []string
	// SomeRequestBodyContains are substrings that must appear in the
	// requestObject of at least one matched event (for expectations that
	// match several writes of which only some carry the string).
	SomeRequestBodyContains []string
	Code                    int               // expected HTTP status, 0 = don't care
	Annotations             map[string]string // expected annotations
	AnnotationsAbsent       []string          // annotation keys that must not be present
	AnnotationsPresent      []string          // annotation keys that must be present, whatever their value
	Impersonated            string            // expected impersonatedUser.username
	ImpersonatedUID         string            // expected impersonatedUser.uid
	ImpersonatedGroups      []string          // each must appear in impersonatedUser.groups
	NoImpersonation         bool              // impersonatedUser must be absent
	UsernameEmpty           bool              // user.username must be empty (authn failure)
	// MinEvents is the minimum number of events that must match (0 = at least one).
	MinEvents int
	// AllowNone makes a hygiene expectation pass when no event matched at all.
	AllowNone bool
	// Gap marks a known limitation: a failed check is reported as "GAP" and
	// does not fail the run. A passing check reports "gap closed".
	Gap string
	// Tier says how binding the expectation is. Invariant expectations hold
	// for any sane audit policy and always fail the run; Baseline ones
	// describe the policy shipped in policy/baseline.yaml and are reported
	// as differences unless the run is strict. Empty means Baseline.
	Tier string
	// Requirement links the expectation to an entry of the requirements list.
	Requirement string
}

// Expectation tiers.
const (
	// Invariant: true of any audit policy worth running. A failure is a real
	// finding whatever policy the cluster uses.
	Invariant = "invariant"
	// Baseline: true of the policy in policy/baseline.yaml. On a cluster
	// running a different policy a failure may simply be a deliberate
	// difference, so it is only fatal in strict mode.
	Baseline = "baseline"
)

// IsInvariant reports whether the expectation must hold for any policy.
func (e Expect) IsInvariant() bool { return e.Tier == Invariant }

type Result struct {
	Scenario string
	Expect   Expect
	Events   []*Event
	Errors   []string
	Skipped  string
	// Strict makes a failed Baseline expectation fatal instead of a DIFF.
	Strict bool
}

// Status is one of PASS, FAIL, DIFF, GAP, GAP-CLOSED, SKIP. DIFF is a failed
// Baseline expectation in a non-strict run: the policy behaves differently
// from the baseline, which may well be intentional.
func (r *Result) Status() string {
	switch {
	case r.Skipped != "":
		return "SKIP"
	case len(r.Errors) == 0 && r.Expect.Gap != "":
		return "GAP-CLOSED"
	case len(r.Errors) == 0:
		return "PASS"
	case r.Expect.Gap != "":
		return "GAP"
	case !r.Strict && !r.Expect.IsInvariant():
		return "DIFF"
	default:
		return "FAIL"
	}
}

// Fatal reports whether the result should fail the run.
func (r *Result) Fatal() bool { return r.Status() == "FAIL" }

const (
	Required  = "required"
	Forbidden = "forbidden"
)

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify checks one expectation against the events of a run. runUA is the
// User-Agent of the run, used by matchers that only look at its own traffic.
func Verify(scn string, ex Expect, events []*Event, runUA string, strict bool) *Result {
	r := &Result{Scenario: scn, Expect: ex, Strict: strict}
	fail := func(format string, args ...any) {
		r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	}
	for _, e := range events {
		if ex.Match.Matches(e, runUA) {
			r.Events = append(r.Events, e)
		}
	}
	if ex.Level == "None" {
		if len(r.Events) > 0 {
			fail("expected no events, found %d (first: %s)", len(r.Events), r.Events[0].Short())
		}
		return r
	}
	if len(r.Events) == 0 {
		if !ex.AllowNone {
			fail("no event matched {%s}", ex.Match)
		}
		return r
	}
	if ex.MinEvents > 0 && len(r.Events) < ex.MinEvents {
		fail("%d events matched, want at least %d", len(r.Events), ex.MinEvents)
	}
	stages := map[string]bool{}
	someContains := map[string]bool{}
	for _, e := range r.Events {
		stages[e.Stage] = true
		if e.Stage == "ResponseComplete" {
			for _, s := range ex.SomeRequestBodyContains {
				if e.PredictedBody || strings.Contains(string(e.RequestObject), s) {
					someContains[s] = true
				}
			}
		}
		if ex.Level != "" && e.Level != ex.Level {
			fail("level %s, want %s: %s", e.Level, ex.Level, e.Short())
		}
		if ex.Code != 0 && e.ResponseStatus != nil && e.ResponseStatus.Code != ex.Code {
			fail("code %v, want %d: %s", e.ResponseStatus, ex.Code, e.Short())
		}
		if ex.RequestBody == Required && len(e.RequestObject) == 0 && e.Stage == "ResponseComplete" {
			fail("requestObject missing: %s", e.Short())
		}
		if ex.RequestBody == Forbidden && len(e.RequestObject) > 0 {
			fail("requestObject present but must be absent: %s", e.Short())
		}
		if ex.ResponseBody == Required && len(e.ResponseObject) == 0 && e.Stage == "ResponseComplete" {
			fail("responseObject missing: %s", e.Short())
		}
		if ex.ResponseBody == Forbidden && len(e.ResponseObject) > 0 {
			fail("responseObject present but must be absent: %s", e.Short())
		}
		if e.Stage == "ResponseComplete" && !e.PredictedBody {
			body := string(e.RequestObject)
			for _, s := range ex.RequestBodyContains {
				if !strings.Contains(body, s) {
					fail("requestObject lacks %q: %s", s, e.Short())
				}
			}
			for _, s := range ex.RequestBodyLacks {
				if strings.Contains(body, s) {
					fail("requestObject contains %q: %s", s, e.Short())
				}
			}
		}
		for k, v := range ex.Annotations {
			if e.Annotations[k] != v {
				fail("annotation %s=%q, want %q: %s", k, e.Annotations[k], v, e.Short())
			}
		}
		for _, k := range ex.AnnotationsPresent {
			if _, ok := e.Annotations[k]; !ok {
				fail("annotation %s missing: %s", k, e.Short())
			}
		}
		for _, k := range ex.AnnotationsAbsent {
			if v, ok := e.Annotations[k]; ok {
				fail("annotation %s=%q present but must be absent: %s", k, v, e.Short())
			}
		}
		if ex.Impersonated != "" && (e.ImpersonatedUser == nil || e.ImpersonatedUser.Username != ex.Impersonated) {
			fail("impersonatedUser %v, want %s: %s", e.ImpersonatedUser, ex.Impersonated, e.Short())
		}
		if ex.ImpersonatedUID != "" && (e.ImpersonatedUser == nil || e.ImpersonatedUser.UID != ex.ImpersonatedUID) {
			fail("impersonatedUser uid %v, want %s: %s", e.ImpersonatedUser, ex.ImpersonatedUID, e.Short())
		}
		if ex.NoImpersonation && e.ImpersonatedUser != nil {
			fail("impersonatedUser %v present but must be absent: %s", e.ImpersonatedUser, e.Short())
		}
		for _, g := range ex.ImpersonatedGroups {
			if !e.ImpersonatedGroupHas(g) {
				groups := []string(nil)
				if e.ImpersonatedUser != nil {
					groups = e.ImpersonatedUser.Groups
				}
				fail("impersonatedUser groups %v lack %q: %s", groups, g, e.Short())
			}
		}
		if ex.UsernameEmpty && e.User.Username != "" {
			fail("username %q, want empty: %s", e.User.Username, e.Short())
		}
	}
	for _, s := range ex.SomeRequestBodyContains {
		if !someContains[s] {
			fail("no matched event has %q in its requestObject", s)
		}
	}
	if len(ex.Stages) > 0 {
		var got []string
		for s := range stages {
			got = append(got, s)
		}
		sort.Strings(got)
		want := append([]string{}, ex.Stages...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			fail("stages %v, want %v", got, want)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Small shared helpers, used by the report and the budget
// ---------------------------------------------------------------------------

// KV is a counted key, ordered by count.
type KV struct {
	Key   string
	Count int
}

// SortedCounts returns the entries of m by descending count, at most limit
// (0 = all).
func SortedCounts(m map[string]int, limit int) []KV {
	var out []KV
	for k, v := range m {
		out = append(out, KV{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// FmtCounts renders counts as "a=3, b=1".
func FmtCounts(m map[string]int, limit int) string {
	var parts []string
	for _, kv := range SortedCounts(m, limit) {
		parts = append(parts, fmt.Sprintf("%s=%d", kv.Key, kv.Count))
	}
	return strings.Join(parts, ", ")
}

// ShortUser trims the long service account prefix for compact display.
func ShortUser(u string) string {
	if u == "" {
		return "<anonymous>"
	}
	if rest, ok := strings.CutPrefix(u, "system:serviceaccount:"); ok {
		return "sa:" + rest
	}
	return u
}

// Contains reports whether list holds s.
func Contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// GroupKey maps the empty API group to "core".
func GroupKey(g string) string {
	if g == "" {
		return "core"
	}
	return g
}
