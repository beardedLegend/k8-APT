// Package compliance maps the run's requirements onto the controls of the
// usual security frameworks, so a finding reads as "this breaks ISO 27001
// A.8.15" rather than only "this breaks R01".
//
// The mapping is deliberately conservative: a control is listed against a
// requirement only where the audit log is actual evidence for it. Controls
// the log is relevant to but cannot prove on its own — retention, log
// integrity, time synchronisation, review — carry a Beyond note, and the
// report shows them as needing evidence from elsewhere instead of as met.
package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/beardedLegend/k8-apt/internal/audit"
	s "github.com/beardedLegend/k8-apt/internal/scenarios"
)

// Framework is one standard; Short is used where space is tight.
type Framework struct {
	Name, Short string
}

var (
	ISO27001 = Framework{"ISO/IEC 27001:2022 Annex A", "ISO 27001"}
	SOC2     = Framework{"SOC 2 Trust Services Criteria (2017, rev. 2022)", "SOC 2"}
	PCIDSS   = Framework{"PCI DSS v4.0", "PCI DSS"}
	NIST     = Framework{"NIST SP 800-53 Rev. 5", "NIST 800-53"}
	CIS      = Framework{"CIS Kubernetes Benchmark", "CIS K8s"}
	BSI      = Framework{"BSI IT-Grundschutz", "BSI"}
)

// Frameworks is the order the report prints them in.
var Frameworks = []Framework{ISO27001, SOC2, PCIDSS, NIST, CIS, BSI}

// Control is one control of a framework and the requirements whose
// expectations are evidence for it.
type Control struct {
	Framework Framework
	ID, Title string
	Reqs      []string
	// Beyond names what the control needs that an audit log cannot show.
	// A control with Beyond and no Reqs is outside what the run can test.
	Beyond string
}

const (
	beyondRetention = "retention of the log for the required period (API server --audit-log-maxage or the log pipeline)"
	beyondIntegrity = "log shipping off the control plane to write-once storage with restricted access"
	beyondTime      = "NTP/chrony on every control plane node"
	beyondReview    = "alerting and a documented review of the log (SIEM rules, on-call)"
	beyondPipeline  = "the log pipeline's own logging: API server restarts and audit policy file changes happen on the node, not through the API"
)

// Controls is the whole mapping.
var Controls = []Control{
	// ---- ISO/IEC 27001:2022 Annex A ------------------------------------
	{ISO27001, "A.5.15", "Access control", []string{s.ReqRBAC, s.ReqAuthFail, s.ReqAnonymous}, ""},
	{ISO27001, "A.5.16", "Identity management", []string{s.ReqHumans, s.ReqImpersonate, s.ReqProxy}, ""},
	{ISO27001, "A.5.17", "Authentication information", []string{s.ReqTokens, s.ReqHygiene}, ""},
	{ISO27001, "A.5.18", "Access rights", []string{s.ReqRBAC}, ""},
	{ISO27001, "A.5.25", "Assessment and decision on information security events", []string{s.ReqIncident}, beyondReview},
	{ISO27001, "A.5.28", "Collection of evidence", []string{s.ReqHumans, s.ReqImpersonate, s.ReqProxy}, beyondIntegrity},
	{ISO27001, "A.5.33", "Protection of records", nil, beyondIntegrity + "; " + beyondRetention},
	{ISO27001, "A.5.34", "Privacy and protection of PII", []string{s.ReqSecrets, s.ReqHygiene}, ""},
	{ISO27001, "A.8.2", "Privileged access rights", []string{s.ReqRBAC, s.ReqExec, s.ReqPrivileged, s.ReqImpersonate}, ""},
	{ISO27001, "A.8.3", "Information access restriction", []string{s.ReqSecrets}, ""},
	{ISO27001, "A.8.5", "Secure authentication", []string{s.ReqAuthFail, s.ReqAnonymous}, ""},
	{ISO27001, "A.8.6", "Capacity management", []string{s.ReqBudget}, ""},
	{ISO27001, "A.8.9", "Configuration management", []string{s.ReqResources, s.ReqEcosystem}, ""},
	{ISO27001, "A.8.11", "Data masking", []string{s.ReqSecrets, s.ReqHygiene}, ""},
	{ISO27001, "A.8.12", "Data leakage prevention", []string{s.ReqSecrets, s.ReqHygiene}, ""},
	{ISO27001, "A.8.15", "Logging", []string{s.ReqResources, s.ReqHumans, s.ReqNoise, s.ReqHygiene, s.ReqEdge}, beyondIntegrity + "; " + beyondRetention},
	{ISO27001, "A.8.16", "Monitoring activities", []string{s.ReqAuthFail, s.ReqIncident}, beyondReview},
	{ISO27001, "A.8.17", "Clock synchronisation", nil, beyondTime},
	{ISO27001, "A.8.18", "Use of privileged utility programs", []string{s.ReqExec, s.ReqPrivileged}, ""},
	{ISO27001, "A.8.32", "Change management", []string{s.ReqResources, s.ReqRBAC, s.ReqEcosystem}, ""},

	// ---- SOC 2 ----------------------------------------------------------
	{SOC2, "CC6.1", "Logical access security", []string{s.ReqAuthFail, s.ReqAnonymous, s.ReqSecrets}, ""},
	{SOC2, "CC6.2", "User registration and credential issuance", []string{s.ReqTokens}, ""},
	{SOC2, "CC6.3", "Role-based access, modification and removal", []string{s.ReqRBAC, s.ReqImpersonate}, ""},
	{SOC2, "CC6.6", "Protection against threats from outside the boundary", []string{s.ReqAnonymous}, ""},
	{SOC2, "CC6.8", "Prevention and detection of unauthorised software", []string{s.ReqPrivileged, s.ReqIncident, s.ReqEcosystem}, ""},
	{SOC2, "CC7.1", "Detection of configuration changes that introduce vulnerabilities", []string{s.ReqResources, s.ReqEcosystem}, ""},
	{SOC2, "CC7.2", "Monitoring of system components for anomalies", []string{s.ReqExec, s.ReqAuthFail, s.ReqHumans, s.ReqIncident}, beyondReview},
	{SOC2, "CC7.3", "Evaluation of security events", []string{s.ReqIncident}, beyondReview},
	{SOC2, "CC7.4", "Incident response", []string{s.ReqImpersonate, s.ReqProxy}, "a documented incident response process that uses the log"},
	{SOC2, "CC8.1", "Change management", []string{s.ReqResources, s.ReqRBAC, s.ReqEcosystem}, ""},
	{SOC2, "C1.1", "Protection of confidential information", []string{s.ReqSecrets, s.ReqHygiene}, ""},
	{SOC2, "A1.1", "Capacity management", []string{s.ReqBudget}, ""},

	// ---- PCI DSS v4.0 ---------------------------------------------------
	{PCIDSS, "8.3.2", "Authentication factors unreadable in storage (no tokens in the log)", []string{s.ReqHygiene}, ""},
	{PCIDSS, "10.2.1", "Audit logs enabled and active", []string{s.ReqResources, s.ReqHumans}, ""},
	{PCIDSS, "10.2.1.1", "Individual access to sensitive data (secrets)", []string{s.ReqSecrets}, ""},
	{PCIDSS, "10.2.1.2", "All actions by individuals with administrative access", []string{s.ReqHumans, s.ReqExec, s.ReqImpersonate}, ""},
	{PCIDSS, "10.2.1.3", "Access to audit logs", nil, beyondIntegrity},
	{PCIDSS, "10.2.1.4", "Invalid logical access attempts", []string{s.ReqAuthFail, s.ReqAnonymous}, ""},
	{PCIDSS, "10.2.1.5", "Changes to identification and authentication credentials", []string{s.ReqTokens, s.ReqRBAC}, ""},
	{PCIDSS, "10.2.1.6", "Initialisation, stopping or pausing of audit logs", nil, beyondPipeline},
	{PCIDSS, "10.2.1.7", "Creation and deletion of system-level objects", []string{s.ReqResources, s.ReqPrivileged, s.ReqEcosystem}, ""},
	{PCIDSS, "10.2.2", "Record content: user, event, outcome, origin, object", []string{s.ReqProxy, s.ReqAuthFail, s.ReqEdge}, ""},
	{PCIDSS, "10.3", "Audit logs protected from destruction and modification", nil, beyondIntegrity},
	{PCIDSS, "10.4", "Audit logs reviewed", nil, beyondReview},
	{PCIDSS, "10.5.1", "Retention: 12 months, 3 months immediately available", []string{s.ReqBudget}, beyondRetention},
	{PCIDSS, "10.6", "Time synchronisation", nil, beyondTime},

	// ---- NIST SP 800-53 Rev. 5 ------------------------------------------
	{NIST, "AC-2(4)", "Automated audit actions (account management)", []string{s.ReqTokens, s.ReqRBAC}, ""},
	{NIST, "AC-6(9)", "Log use of privileged functions", []string{s.ReqRBAC, s.ReqExec, s.ReqPrivileged, s.ReqImpersonate}, ""},
	{NIST, "AU-2", "Event logging", []string{s.ReqResources, s.ReqAuthFail, s.ReqHumans, s.ReqNoise}, ""},
	{NIST, "AU-3", "Content of audit records", []string{s.ReqImpersonate, s.ReqProxy, s.ReqEdge}, ""},
	{NIST, "AU-3(3)", "Limit personally identifiable information elements", []string{s.ReqSecrets, s.ReqHygiene}, ""},
	{NIST, "AU-4", "Audit log storage capacity", []string{s.ReqBudget}, ""},
	{NIST, "AU-6", "Audit record review, analysis and reporting", nil, beyondReview},
	{NIST, "AU-8", "Time stamps", nil, beyondTime},
	{NIST, "AU-9", "Protection of audit information", nil, beyondIntegrity},
	{NIST, "AU-10", "Non-repudiation", []string{s.ReqImpersonate, s.ReqProxy}, ""},
	{NIST, "AU-11", "Audit record retention", nil, beyondRetention},
	{NIST, "AU-12", "Audit record generation", []string{s.ReqResources, s.ReqHumans, s.ReqIncident}, ""},
	{NIST, "CM-3", "Configuration change control", []string{s.ReqResources, s.ReqEcosystem}, ""},
	{NIST, "SI-4", "System monitoring", []string{s.ReqExec, s.ReqIncident}, beyondReview},

	// ---- CIS Kubernetes Benchmark ---------------------------------------
	{CIS, "1.2 audit-log-*", "API server writes the audit log with age, backup and size limits", nil, "the kube-apiserver flags --audit-log-path, --audit-log-maxage, --audit-log-maxbackup and --audit-log-maxsize"},
	{CIS, "3.2.1", "A minimal audit policy is created", []string{s.ReqResources, s.ReqHumans}, ""},
	{CIS, "3.2.2", "The audit policy covers key security concerns", []string{s.ReqSecrets, s.ReqTokens, s.ReqExec, s.ReqResources}, ""},

	// ---- BSI IT-Grundschutz (module level) ------------------------------
	{BSI, "OPS.1.1.5", "Protokollierung (logging)", []string{s.ReqHumans, s.ReqNoise, s.ReqHygiene, s.ReqBudget}, beyondIntegrity},
	{BSI, "DER.1", "Detektion von sicherheitsrelevanten Ereignissen (detection)", []string{s.ReqAuthFail, s.ReqIncident}, beyondReview},
	{BSI, "APP.4.4", "Kubernetes", []string{s.ReqExec, s.ReqPrivileged, s.ReqImpersonate, s.ReqSecrets}, ""},
}

// Control statuses, worst first.
const (
	Fail      = "FAIL"      // a requirement it rests on failed
	Gap       = "GAP"       // a requirement it rests on has a known gap
	Diff      = "DIFF"      // the policy differs from the baseline there
	NotTested = "UNTESTED"  // no expectation behind it ran (skipped or not applicable)
	Met       = "MET"       // every expectation behind it passed
	Elsewhere = "ELSEWHERE" // nothing the run can test; evidence lives elsewhere
)

var rank = map[string]int{Fail: 0, Gap: 1, Diff: 2, NotTested: 3, Met: 4, Elsewhere: 5}

// Assessment is the state of one control after a run.
type Assessment struct {
	Control
	Status string
	// Findings are the requirements that pulled the status down, each with
	// how many of its expectations did.
	Findings []string
}

// Assess derives the state of every control from the run's results.
func Assess(results []*audit.Result) []Assessment {
	type tally struct{ fail, gap, diff, pass, skip int }
	byReq := map[string]*tally{}
	for _, r := range results {
		t := byReq[r.Expect.Requirement]
		if t == nil {
			t = &tally{}
			byReq[r.Expect.Requirement] = t
		}
		switch r.Status() {
		case "FAIL":
			t.fail++
		case "GAP":
			t.gap++
		case "DIFF":
			t.diff++
		case "SKIP":
			t.skip++
		default:
			t.pass++
		}
	}

	out := make([]Assessment, 0, len(Controls))
	for _, c := range Controls {
		a := Assessment{Control: c, Status: Met}
		if len(c.Reqs) == 0 {
			a.Status = Elsewhere
			out = append(out, a)
			continue
		}
		tested := false
		worse := func(st string, req string, n int, what string) {
			if n == 0 {
				return
			}
			if rank[st] < rank[a.Status] {
				a.Status = st
			}
			if n > 1 {
				what += "s"
			}
			a.Findings = append(a.Findings, fmt.Sprintf("%s %d %s", reqID(req), n, what))
		}
		for _, req := range c.Reqs {
			t := byReq[req]
			if t == nil {
				continue
			}
			if t.pass+t.fail+t.gap+t.diff > 0 {
				tested = true
			}
			worse(Fail, req, t.fail, "failure")
			worse(Gap, req, t.gap, "known gap")
			worse(Diff, req, t.diff, "difference")
		}
		if !tested {
			a.Status = NotTested
		}
		out = append(out, a)
	}
	return out
}

// ForRequirement lists the controls a requirement is evidence for, as
// "ISO 27001 A.8.15, A.8.32 · SOC 2 CC8.1" in framework order.
func ForRequirement(req string) string {
	byFw := map[string][]string{}
	for _, c := range Controls {
		if audit.Contains(c.Reqs, req) {
			byFw[c.Framework.Short] = append(byFw[c.Framework.Short], c.ID)
		}
	}
	var parts []string
	for _, fw := range Frameworks {
		if ids := byFw[fw.Short]; len(ids) > 0 {
			parts = append(parts, fw.Short+" "+strings.Join(ids, ", "))
		}
	}
	return strings.Join(parts, " · ")
}

// ByStatus orders assessments worst first, keeping framework order within a
// status.
func ByStatus(as []Assessment) []Assessment {
	out := append([]Assessment{}, as...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Status] < rank[out[j].Status] })
	return out
}

// reqID shortens "R01 resource creation and modification" to "R01".
func reqID(req string) string {
	if i := strings.IndexByte(req, ' '); i > 0 {
		return req[:i]
	}
	return req
}
