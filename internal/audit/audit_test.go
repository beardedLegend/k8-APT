package audit

import "testing"

func TestAnnotationsPresent(t *testing.T) {
	ex := Expect{
		Desc:               "annotated",
		Match:              Match{Verb: "create", AnyUA: true},
		AnnotationsPresent: []string{"pod-security.kubernetes.io/audit-violations"},
	}
	with := &Event{Verb: "create", Stage: "ResponseComplete", Annotations: map[string]string{"pod-security.kubernetes.io/audit-violations": "would violate"}}
	without := &Event{Verb: "create", Stage: "ResponseComplete"}

	if r := Verify("t", ex, []*Event{with}, "", true); r.Status() != "PASS" {
		t.Errorf("annotation present: %s %v", r.Status(), r.Errors)
	}
	if r := Verify("t", ex, []*Event{without}, "", true); r.Status() != "FAIL" {
		t.Errorf("annotation missing: %s, want FAIL", r.Status())
	}
}
