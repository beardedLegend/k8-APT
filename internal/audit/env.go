package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/your-org/k8-apt/internal/config"
)

// Env is the context of one run: the cluster profile, the clients, the names
// derived from the run id, and the values that must never turn up in the log.
type Env struct {
	Cfg *config.Cluster

	// RunID is unique per run and appears in every name the run creates, so
	// that its events can be told apart from everyone else's.
	RunID string
	// UserAgent is sent with every request of the run.
	UserAgent string
	// Namespace is the throw-away namespace the run works in.
	Namespace string
	// Start is when the run began, ActStart when it stopped idling and
	// started acting (see the budget).
	Start    time.Time
	ActStart time.Time

	// AdminUser is the identity the run's own requests appear under.
	AdminUser string
	// Domain is the DNS domain used for test labels, CRDs and webhooks.
	Domain string
	// Image is the container image of the test pods.
	Image string

	// ProxyUser and ProxyGroups are the end-user identity impersonated by the
	// proxy scenarios; ProxySA is the proxy's own account.
	ProxySA     string
	ProxyUser   string
	ProxyGroups []string

	// Nodes discovered at start-up.
	ControlPlaneNodes []string
	WorkerNodes       []string

	// RogueNode is the node identity impersonated by the rogue-node scenario;
	// WorkerNode the node the first test pod landed on; TaintedNode is set
	// while a test taint is on a node, so cleanup can find it.
	RogueNode   string
	WorkerNode  string
	TaintedNode string

	RestConfig *rest.Config
	Client     *kubernetes.Clientset
	Dynamic    dynamic.Interface

	// IssuedCert/IssuedKey hold the client certificate issued for the test
	// CSR, when the cluster has a signer for kubernetes.io/kube-apiserver-client.
	IssuedCert []byte
	IssuedKey  []byte

	markers   map[string]string
	markersMu sync.Mutex

	Logs LogSource
}

// AddMarker records a value that must never appear anywhere in the log
// (a secret value, an issued token).
func (env *Env) AddMarker(what, value string) {
	env.markersMu.Lock()
	defer env.markersMu.Unlock()
	env.markers[what] = value
}

// Markers returns a copy of the recorded values.
func (env *Env) Markers() map[string]string {
	env.markersMu.Lock()
	defer env.markersMu.Unlock()
	out := map[string]string{}
	for k, v := range env.markers {
		out[k] = v
	}
	return out
}

// Name builds a unique cluster-scoped object name for this run.
func (env *Env) Name(suffix string) string {
	return env.Cfg.NamespacePrefix + "-" + env.RunID + "-" + suffix
}

// Label builds a label or annotation key in the run's test domain.
func (env *Env) Label(name string) string { return env.Domain + "/" + name }

// ConfigFor returns a copy of the rest config carrying the run's User-Agent.
func (env *Env) ConfigFor(mod func(c *rest.Config)) *rest.Config {
	c := rest.CopyConfig(env.RestConfig)
	c.UserAgent = env.UserAgent
	if mod != nil {
		mod(c)
	}
	return c
}

// AnonymousConfig returns a config that presents no credentials at all.
func (env *Env) AnonymousConfig() *rest.Config {
	c := rest.AnonymousClientConfig(env.RestConfig)
	c.UserAgent = env.UserAgent
	return c
}

// ProxySANamespace / ProxySAName are the proxy's own service account.
func (env *Env) ProxySANamespace() string {
	return env.Cfg.Component.Proxy.ServiceAccountNamespace
}

func (env *Env) ProxySAName() string { return env.Cfg.Component.Proxy.ServiceAccountName }

// ManagedGroups / StatusGroups / SystemUsers expose the policy expectations.
func (env *Env) ManagedGroups() []string { return env.Cfg.Expect.ManagedGroups }
func (env *Env) StatusGroups() []string  { return env.Cfg.Expect.StatusGroups }
func (env *Env) SystemUsers() []string   { return env.Cfg.Expect.SystemUsers }

// runID is short, lowercase and sortable: base36 of the unix time.
func runID(now time.Time) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	n := now.Unix()
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%36]}, b...)
		n /= 36
	}
	return string(b)
}

// NewEnv builds the clients, discovers the cluster's identity and nodes, and
// prepares the log source.
func NewEnv(ctx context.Context, cfg *config.Cluster) (*Env, error) {
	restCfg, err := restConfig(cfg)
	if err != nil {
		return nil, err
	}
	id := runID(time.Now())
	env := &Env{
		Cfg:       cfg,
		RunID:     id,
		UserAgent: "k8-apt/" + id,
		Namespace: cfg.NamespacePrefix + "-" + id,
		Start:     time.Now(),
		Domain:    cfg.TestDomain,
		Image:     cfg.Image,
		markers:   map[string]string{},
	}
	restCfg.UserAgent = env.UserAgent
	env.RestConfig = restCfg
	if env.Client, err = kubernetes.NewForConfig(restCfg); err != nil {
		return nil, err
	}
	if env.Dynamic, err = dynamic.NewForConfig(restCfg); err != nil {
		return nil, err
	}

	if p := cfg.Component.Proxy; p.Enabled {
		env.ProxySA = p.ProxySA()
		env.ProxyUser = p.User
		if env.ProxyUser == "" {
			env.ProxyUser = "audit-user-" + id + "@" + cfg.TestDomain
		}
		env.ProxyGroups = p.Groups
	}

	env.AdminUser = cfg.AdminUser
	if env.AdminUser == "" {
		if env.AdminUser, err = whoami(ctx, env.Client); err != nil {
			return nil, fmt.Errorf("detect own identity (set adminUser in the profile to skip): %w", err)
		}
	}
	if err := env.discoverNodes(ctx); err != nil {
		return nil, err
	}
	if env.Logs, err = newLogSource(env); err != nil {
		return nil, err
	}
	return env, nil
}

func restConfig(cfg *config.Cluster) (*rest.Config, error) {
	if cfg.Kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	c, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err == nil {
		return c, nil
	}
	if ic, icErr := rest.InClusterConfig(); icErr == nil {
		return ic, nil
	}
	return nil, fmt.Errorf("no kubeconfig: set kubeconfig in the profile, --kubeconfig or $KUBECONFIG (%w)", err)
}

// whoami asks the API server which user the current credentials authenticate
// as, so that the expectations can match on it whatever the authentication
// method is (certificates, OIDC, a token issued by an external CA).
func whoami(ctx context.Context, c *kubernetes.Clientset) (string, error) {
	r, err := c.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if r.Status.UserInfo.Username == "" {
		return "", fmt.Errorf("SelfSubjectReview returned no username")
	}
	return r.Status.UserInfo.Username, nil
}

// discoverNodes records the control plane and worker nodes; the control plane
// addresses double as the default ssh targets for the log source.
func (env *Env) discoverNodes(ctx context.Context) error {
	nodes, err := env.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	for _, n := range nodes.Items {
		_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
		if !cp {
			_, cp = n.Labels["node-role.kubernetes.io/master"]
		}
		addr := n.Name
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP && a.Address != "" {
				addr = a.Address
				break
			}
		}
		if cp {
			env.ControlPlaneNodes = append(env.ControlPlaneNodes, addr)
		} else {
			env.WorkerNodes = append(env.WorkerNodes, n.Name)
		}
	}
	if len(nodes.Items) == 0 {
		return fmt.Errorf("cluster reports no nodes")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Log sources
// ---------------------------------------------------------------------------

// LogSource yields the audit events written since Begin was called.
type LogSource interface {
	// Begin records where the log stands now, so that a later Fetch returns
	// only what was appended afterwards. Nothing is ever truncated.
	Begin(ctx context.Context) error
	Fetch(ctx context.Context) ([]*Event, error)
	Describe() string
}

func newLogSource(env *Env) (LogSource, error) {
	l := env.Cfg.Log
	if l.Type == "files" {
		return &fileSource{files: l.Files}, nil
	}
	hosts := l.Hosts
	if len(hosts) == 0 {
		if len(env.ControlPlaneNodes) == 0 {
			return nil, fmt.Errorf("no control plane nodes found and log.hosts is empty")
		}
		hosts = env.ControlPlaneNodes
	}
	user := l.SSHUser
	full := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if !strings.Contains(h, "@") && user != "" {
			h = user + "@" + h
		}
		full = append(full, h)
	}
	opts := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	opts = append(opts, l.SSHOptions...)
	return &sshSource{
		hosts:   full,
		sshOpts: opts,
		sudo:    l.SudoEnabled(),
		path:    l.Path,
		offsets: map[string]int64{},
	}, nil
}

type fileSource struct {
	files []string
}

func (f *fileSource) Describe() string            { return "files " + strings.Join(f.files, ",") }
func (f *fileSource) Begin(context.Context) error { return nil }
func (f *fileSource) Fetch(context.Context) ([]*Event, error) {
	var all []*Event
	for _, p := range f.files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		evs, err := ParseEvents(raw, filepath.Base(p))
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	return all, nil
}
