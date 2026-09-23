// Package config holds the cluster profile: everything k8-apt needs to know
// about a cluster that it cannot discover for itself.
//
// Every field has a default that works on a stock Kubernetes cluster, so an
// empty profile is a valid profile. A cluster that runs extra operators, that
// keeps its audit log somewhere unusual or that is reached through an
// authenticating proxy describes that here rather than in the code.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Cluster is the profile of the cluster under test.
type Cluster struct {
	// APIVersion/Kind are accepted and ignored, so a profile can carry them
	// for editor tooling.
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`

	// Kubeconfig to authenticate with. Empty uses $KUBECONFIG, then
	// ~/.kube/config, then the in-cluster config.
	Kubeconfig string `json:"kubeconfig,omitempty"`

	// AdminUser is the username the tool's own requests appear under in the
	// audit log. Empty means: ask the API server at start-up
	// (SelfSubjectReview), which is right for every authentication method.
	AdminUser string `json:"adminUser,omitempty"`

	// TestDomain is the DNS domain used for the labels, annotations, CRD
	// groups and webhook names the scenarios create. It never needs to
	// resolve; it only has to be a domain nothing else on the cluster uses.
	TestDomain string `json:"testDomain,omitempty"`

	// Namespace is the prefix of the throw-away namespace each run creates
	// (the run id is appended).
	NamespacePrefix string `json:"namespacePrefix,omitempty"`

	// Image is the container image the test pods run. It must exist for the
	// cluster's architecture and be pullable from the nodes.
	Image string `json:"image,omitempty"`

	// Settle is how long to wait after the last request before reading the
	// audit log, so the API server has flushed it.
	Settle Duration `json:"settle,omitempty"`

	// IdleSample makes the run idle for this long before acting, to measure
	// the cluster's background log volume without the run's own traffic.
	IdleSample Duration `json:"idleSample,omitempty"`

	Log       LogSource `json:"log"`
	Budget    Budget    `json:"budget"`
	Expect    Expect    `json:"expect"`
	Component Component `json:"components"`
}

// LogSource says where the audit log of the cluster can be read.
type LogSource struct {
	// Type is "ssh" (read the log from the control plane nodes over ssh) or
	// "files" (read local copies, for offline verification).
	Type string `json:"type,omitempty"`

	// Path is the audit log path on the control plane nodes.
	Path string `json:"path,omitempty"`

	// Hosts are "[user@]host" entries. Empty means: discover the control
	// plane nodes through the API (nodes labelled
	// node-role.kubernetes.io/control-plane or .../master) and use their
	// internal addresses.
	Hosts []string `json:"hosts,omitempty"`

	// SSHUser is used for discovered hosts that carry no user.
	SSHUser string `json:"sshUser,omitempty"`

	// SSHOptions are extra options passed to ssh, e.g.
	// ["-o", "UserKnownHostsFile=/path/known_hosts"].
	SSHOptions []string `json:"sshOptions,omitempty"`

	// Sudo runs the read commands through sudo (the default: audit logs are
	// normally root-readable only).
	Sudo *bool `json:"sudo,omitempty"`

	// Files are the local files to read when Type is "files".
	Files []string `json:"files,omitempty"`
}

// Budget is the log volume the cluster is allowed to produce.
type Budget struct {
	// GBPerYear is the yearly budget for the whole cluster. The check
	// extrapolates the measured idle rate to a year and compares.
	GBPerYear float64 `json:"gbPerYear,omitempty"`
}

// Expect describes what the audit policy under test is expected to do. The
// defaults describe the baseline policy shipped in policy/baseline.yaml; a
// cluster running a different policy adjusts them here (or runs with
// --no-strict and reads the differences off the report).
type Expect struct {
	// ManagedGroups are the user groups whose reads and status writes the
	// policy is expected to drop: the cluster's own components. The baseline
	// drops nothing by group, so the default is empty; set it when the
	// cluster runs policy/hardened.yaml or a policy like it.
	ManagedGroups []string `json:"managedGroups,omitempty"`

	// StatusGroups are the API groups whose */status writes the policy is
	// expected to drop for those groups.
	StatusGroups []string `json:"statusGroups,omitempty"`

	// SystemUsers are the non-service-account control plane identities whose
	// reads the policy is expected to drop.
	SystemUsers []string `json:"systemUsers,omitempty"`
}

// Component switches on the scenarios that only make sense on a cluster that
// runs the component in question.
type Component struct {
	Proxy   ProxyComponent   `json:"proxy"`
	Calico  CalicoComponent  `json:"calico"`
	Metrics MetricsComponent `json:"metrics"`
}

// ProxyComponent describes an authenticating proxy that presents its own
// service account to the API server and impersonates the end user behind it
// (a VPN gateway, an SSO portal, a managed-access broker). Those scenarios
// check that the audit log still names the human behind the proxy.
//
// Note that Kubernetes evaluates the audit policy against the *real* user —
// the proxy's own account — and not against the impersonated one, so a policy
// that treats the proxy as a system component silently drops or truncates
// everything the end users do through it. That is what these scenarios look
// for.
type ProxyComponent struct {
	Enabled bool `json:"enabled,omitempty"`
	// ServiceAccountNamespace/Name identify the proxy's own account, for
	// which the run mints a token.
	ServiceAccountNamespace string `json:"serviceAccountNamespace,omitempty"`
	ServiceAccountName      string `json:"serviceAccountName,omitempty"`
	// User and Groups are the end-user identity the proxy impersonates. The
	// user defaults to a unique, non-existent test identity; the group has
	// to be one the cluster grants rights to, or the scenarios only see 403s.
	User   string   `json:"user,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// CalicoComponent enables the Calico scenarios: the aggregated
// projectcalico.org API (whose bodies the API server cannot record) and the
// crd.projectcalico.org objects behind it.
type CalicoComponent struct {
	Enabled bool `json:"enabled,omitempty"`
}

// MetricsComponent notes whether metrics-server is installed, which decides
// whether `kubectl top` style reads answer 200 or 404. Either way they must
// be logged; the scenario only uses this for its description.
type MetricsComponent struct {
	Installed bool `json:"installed,omitempty"`
}

// Duration is a time.Duration that marshals as a string ("10m").
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Default returns the profile of a stock cluster: the components are off and
// the expectations describe the baseline policy.
func Default() *Cluster {
	t := true
	return &Cluster{
		APIVersion:      "k8-apt.dev/v1",
		Kind:            "ClusterProfile",
		TestDomain:      "audit-test.example.com",
		NamespacePrefix: "audit-test",
		Image:           "busybox:1.36",
		Settle:          Duration(5 * time.Second),
		Log: LogSource{
			Type:    "ssh",
			Path:    "/var/log/kubernetes/audit/audit.log",
			SSHUser: "root",
			Sudo:    &t,
		},
		Budget: Budget{GBPerYear: 36.5},
		Expect: Expect{
			StatusGroups: []string{
				"core", "apps", "batch", "autoscaling", "policy",
				"networking.k8s.io", "storage.k8s.io", "certificates.k8s.io",
				"apiextensions.k8s.io", "apiregistration.k8s.io",
				"admissionregistration.k8s.io",
			},
			SystemUsers: []string{
				"system:kube-controller-manager",
				"system:kube-scheduler",
				"system:apiserver",
			},
		},
	}
}

// Load reads a profile from a file and fills every unset field with its
// default. An empty path returns the defaults.
func Load(path string) (*Cluster, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Unmarshal onto the defaults so that omitted fields keep them, then
	// repair the slices: a profile that sets a list replaces it, and one
	// that sets it empty means empty.
	var probe map[string]any
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := yaml.UnmarshalStrict(raw, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.resolvePaths(filepath.Dir(path))
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// resolvePaths makes the file paths in a profile relative to the profile
// itself rather than to the working directory, so that a profile can be
// checked in next to the kubeconfig it names and used from anywhere.
func (c *Cluster) resolvePaths(dir string) {
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "~") {
			return p
		}
		return filepath.Join(dir, p)
	}
	c.Kubeconfig = rel(c.Kubeconfig)
	for i, f := range c.Log.Files {
		c.Log.Files[i] = rel(f)
	}
}

func (c *Cluster) Validate() error {
	switch c.Log.Type {
	case "ssh", "files", "":
	default:
		return fmt.Errorf("log.type %q: want \"ssh\" or \"files\"", c.Log.Type)
	}
	if c.Log.Type == "files" && len(c.Log.Files) == 0 {
		return fmt.Errorf("log.type is \"files\" but log.files is empty")
	}
	if c.TestDomain == "" {
		return fmt.Errorf("testDomain must not be empty")
	}
	if strings.ContainsAny(c.TestDomain, "/ ") {
		return fmt.Errorf("testDomain %q must be a bare DNS name", c.TestDomain)
	}
	if c.Budget.GBPerYear < 0 {
		return fmt.Errorf("budget.gbPerYear must not be negative")
	}
	p := c.Component.Proxy
	if p.Enabled && (p.ServiceAccountNamespace == "" || p.ServiceAccountName == "") {
		return fmt.Errorf("components.proxy.enabled needs serviceAccountNamespace and serviceAccountName")
	}
	return nil
}

// SudoEnabled reports whether log reads go through sudo.
func (l LogSource) SudoEnabled() bool { return l.Sudo == nil || *l.Sudo }

// ProxySA is the username of the proxy's own service account.
func (p ProxyComponent) ProxySA() string {
	return "system:serviceaccount:" + p.ServiceAccountNamespace + ":" + p.ServiceAccountName
}

// Marshal renders the profile as commented-free YAML, for `k8-apt config`.
func (c *Cluster) Marshal() ([]byte, error) { return yaml.Marshal(c) }
