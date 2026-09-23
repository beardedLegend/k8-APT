// Package policy embeds the audit policies shipped with k8-apt, so the binary
// can start from the baseline without a checkout.
package policy

import _ "embed"

// Baseline is policy/baseline.yaml: the example policy from the Kubernetes
// documentation, which the default expectations describe.
//
//go:embed baseline.yaml
var Baseline []byte
