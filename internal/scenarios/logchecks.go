package scenarios

import (
	"fmt"
	"strings"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

// LogChecks are the checks over the raw log that no matcher expresses: the
// values the run planted must never appear, and bodies must not carry
// managedFields.
func LogChecks(env *audit.Env, events []*audit.Event, strict bool) []*audit.Result {
	return []*audit.Result{credentialLeakCheck(env, events, strict), managedFieldsCheck(events, strict)}
}

// credentialLeakCheck scans every event for the secret values and tokens the
// run created. This holds for any audit policy, so it is an invariant.
func credentialLeakCheck(env *audit.Env, events []*audit.Event, strict bool) *audit.Result {
	r := &audit.Result{
		Scenario: "global",
		Expect: audit.Expect{
			Desc:        "secret values and issued tokens never appear in the log",
			Requirement: ReqHygiene,
			Tier:        audit.Invariant,
		},
		Strict: strict,
	}
	for what, value := range env.Markers() {
		for _, e := range events {
			if strings.Contains(e.Raw, value) {
				r.Errors = append(r.Errors, fmt.Sprintf("%s leaked: %s", what, e.Short()))
				r.Events = append(r.Events, e)
			}
		}
	}
	return r
}

func managedFieldsCheck(events []*audit.Event, strict bool) *audit.Result {
	r := &audit.Result{
		Scenario: "global",
		Expect: audit.Expect{
			Desc:        "bodies never contain managedFields",
			Requirement: ReqHygiene,
			Gap:         GapManagedFields,
		},
		Strict: strict,
	}
	for _, e := range events {
		if strings.Contains(string(e.RequestObject), `"managedFields"`) ||
			strings.Contains(string(e.ResponseObject), `"managedFields"`) {
			r.Errors = append(r.Errors, "managedFields in "+e.Short())
		}
	}
	return r
}
