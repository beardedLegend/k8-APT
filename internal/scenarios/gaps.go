package scenarios

// The baseline policy is the example policy from the Kubernetes
// documentation (policy/baseline.yaml). Where that policy records less than a
// security-minded operator would want, the expectation keeps asking for more
// and carries one of these explanations as its Gap: the run reports it, never
// fails on it, and says "gap closed" once the cluster's policy does better.
const (
	// gapNonCoreBody: the example logs the core group at Request and every
	// other group at Metadata, so writes to apps, rbac, admission, CRDs and
	// operator groups say that something changed but not what.
	gapNonCoreBody = "the baseline logs every API group other than core and extensions at Metadata, so this write has no body; add a level: Request rule for the group to record what changed"

	// gapNoise: the example has almost no drop rules, so component chatter
	// is logged. Correct for completeness, expensive for the budget.
	gapNoise = "the baseline has no rule for this component traffic, so it is logged; add a level: None rule for it if the log volume matters"

	// GapManagedFields: the example does not set omitManagedFields, and pods
	// are logged at RequestResponse, whose response carries managedFields.
	GapManagedFields = "the baseline does not set omitManagedFields: true, so request and response bodies carry managedFields"
)
