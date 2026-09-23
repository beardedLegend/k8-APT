package policygen

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/beardedLegend/k8-apt/internal/audit"
	"github.com/beardedLegend/k8-apt/internal/auditpolicy"
)

// placeholder stands in for a body the new policy would record but the log
// never did.
var placeholder = json.RawMessage(`{"k8-apt":"predicted"}`)

// simulate predicts the log the run would have produced with rules placed
// ahead of the cluster's policy. The result is aligned with events; a nil
// entry is an event the new rules drop.
//
// Only the new rules are evaluated. An event none of them matches falls
// through to the cluster's own policy, whose verdict is the level the event
// was actually logged at, so the prediction needs no copy of that policy.
// What it cannot predict is traffic the cluster's policy dropped: those
// requests are not in the log to be re-levelled.
func simulate(events []*audit.Event, rules []auditpolicy.Rule, omitManagedFields bool) []*audit.Event {
	out := make([]*audit.Event, len(events))
	for i, e := range events {
		idx := auditpolicy.First(rules, e)
		if idx < 0 {
			out[i] = e
			if omitManagedFields {
				out[i] = withoutManagedFields(e)
			}
			continue
		}
		r := &rules[idx]
		if r.Level == "None" || audit.Contains(r.OmitStages, e.Stage) {
			continue
		}
		c := *e
		c.Level = r.Level
		switch r.Level {
		case "Metadata":
			c.RequestObject, c.ResponseObject = nil, nil
		case "Request":
			c.ResponseObject = nil
			if len(c.RequestObject) == 0 && carriesBody(e) {
				c.RequestObject, c.PredictedBody = placeholder, true
			}
		case "RequestResponse":
			if len(c.RequestObject) == 0 && carriesBody(e) {
				c.RequestObject, c.PredictedBody = placeholder, true
			}
			if len(c.ResponseObject) == 0 && e.Stage == "ResponseComplete" && e.Verb != "watch" {
				c.ResponseObject = placeholder
			}
		}
		if omitManagedFields {
			c.RequestObject = stripManagedFields(c.RequestObject)
			c.ResponseObject = stripManagedFields(c.ResponseObject)
		}
		c.Raw = rewriteRaw(e, &c)
		out[i] = &c
	}
	return out
}

// carriesBody reports whether the request behind e has a body the API server
// would record at Request level: a write that reached decoding.
func carriesBody(e *audit.Event) bool {
	if e.Stage != "ResponseComplete" {
		return false
	}
	switch e.Verb {
	case "create", "update", "patch", "delete", "deletecollection":
	default:
		return false
	}
	if e.ResponseStatus != nil {
		switch e.ResponseStatus.Code {
		case 400, 401, 415:
			return false
		case 403:
			// Denied by authorization: rejected before the body was decoded.
			if e.Annotations["authorization.k8s.io/decision"] == "forbid" {
				return false
			}
		}
	}
	return true
}

func withoutManagedFields(e *audit.Event) *audit.Event {
	req, resp := stripManagedFields(e.RequestObject), stripManagedFields(e.ResponseObject)
	if len(req) == len(e.RequestObject) && len(resp) == len(e.ResponseObject) {
		return e
	}
	c := *e
	c.RequestObject, c.ResponseObject = req, resp
	c.Raw = rewriteRaw(e, &c)
	return &c
}

// stripManagedFields removes metadata.managedFields from an object or from
// every item of a list, as omitManagedFields does.
func stripManagedFields(body json.RawMessage) json.RawMessage {
	if !bytes.Contains(body, []byte(`"managedFields"`)) {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	strip := func(o map[string]any) {
		if md, ok := o["metadata"].(map[string]any); ok {
			delete(md, "managedFields")
		}
	}
	strip(obj)
	if items, ok := obj["items"].([]any); ok {
		for _, it := range items {
			if o, ok := it.(map[string]any); ok {
				strip(o)
			}
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return b
}

// rewriteRaw carries the changes of a simulated event into its raw line, so
// that its size (for the budget) and its content (for the leak check) follow.
func rewriteRaw(orig, sim *audit.Event) string {
	raw := orig.Raw
	swap := func(key string, before, after json.RawMessage) {
		if len(before) == 0 || bytes.Equal(before, after) {
			return
		}
		repl := "null"
		if len(after) > 0 {
			repl = string(after)
		}
		raw = strings.Replace(raw, `"`+key+`":`+string(before), `"`+key+`":`+repl, 1)
	}
	swap("requestObject", orig.RequestObject, sim.RequestObject)
	swap("responseObject", orig.ResponseObject, sim.ResponseObject)
	if orig.Level != sim.Level {
		raw = strings.Replace(raw, `"level":"`+orig.Level+`"`, `"level":"`+sim.Level+`"`, 1)
	}
	return raw
}
