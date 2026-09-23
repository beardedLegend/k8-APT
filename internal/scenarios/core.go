// Package scenarios holds everything a run does to the cluster and what it
// then expects to find in the audit log.
//
// A Scenario has two halves: Act performs requests, Expect declares what the
// audit log must contain because of them. They are separated in time — every
// scenario acts first, then the log is fetched once and every expectation is
// checked against it — so an expectation may look at events the scenario did
// not cause itself (a controller reacting to it, a kubelet, another node).
package scenarios

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	nodev1 "k8s.io/api/node/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/client-go/util/retry"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

// Requirement keys. Each expectation names the requirement it covers, and the
// report groups coverage by them.
const (
	ReqResources   = "R01 resource creation and modification"
	ReqRBAC        = "R02 Role/RoleBinding creation and modification"
	ReqExec        = "R03 container execution (exec/attach/portforward)"
	ReqPrivileged  = "R04 privileged pod creation"
	ReqAuthFail    = "R05 authn/authz failures"
	ReqAnonymous   = "R06 anonymous requests"
	ReqImpersonate = "R07 impersonation"
	ReqTokens      = "R08 token and CSR issuance"
	ReqSecrets     = "R09 access to secrets (without secret data)"
	ReqHumans      = "R10 everything humans do"
	ReqNoise       = "R11 noise suppression (system components)"
	ReqHygiene     = "R12 log hygiene (no credential bodies, no managedFields, no RequestReceived)"
	ReqProxy       = "R13 proxied access attributed to the real end user"
	ReqIncident    = "R14 simulated security incidents are captured"
)

// Scenario is one coherent piece of cluster usage plus what the audit log
// must show for it.
type Scenario struct {
	Name string
	// Act performs the requests. A returned error fails the scenario unless
	// Optional is set, in which case the scenario is skipped.
	Act    func(ctx context.Context, env *audit.Env) error
	Expect func(env *audit.Env) []audit.Expect
	// Optional marks a scenario whose Act failure is a skip rather than a
	// failure: the cluster may simply not have what it needs.
	Optional bool
	// Needs, when set, decides whether the scenario applies to this cluster
	// at all (a component switched off in the profile).
	Needs func(env *audit.Env) bool
}

const (
	podPlain      = "plain"
	podPrivileged = "privileged"
	podEvict      = "evictme"
	podDelColl    = "delcoll"
	podWorkerPriv = "worker-privileged"
	deployName    = "audit-deploy"
	secretName    = "audit-secret"
	saRestricted  = "restricted"
	saWorker      = "worker"
)

func int32p(i int32) *int32 { return &i }
func boolp(b bool) *bool    { return &b }
func int64p(i int64) *int64 { return &i }

func sleepPod(name, image string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: int64p(1),
			Containers: []corev1.Container{{
				Name:    "main",
				Image:   image,
				Command: []string{"sh", "-c", "sleep 3600"},
			}},
		},
	}
}

func waitPodRunning(ctx context.Context, c kubernetes.Interface, ns, name string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	for {
		p, err := c.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if p.Status.Phase == corev1.PodRunning {
			return p, nil
		}
		if p.Status.Phase == corev1.PodFailed {
			return p, fmt.Errorf("pod %s failed: %s", name, p.Status.Reason)
		}
		if time.Now().After(deadline) {
			return p, fmt.Errorf("pod %s not running after %s (phase %s)", name, timeout, p.Status.Phase)
		}
		time.Sleep(2 * time.Second)
	}
}

func ignoreForbidden(err error) error {
	if err != nil && (apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err)) {
		return nil
	}
	return err
}

func ignoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func tokenFor(ctx context.Context, env *audit.Env, ns, sa string) (string, error) {
	tr, err := env.Client.CoreV1().ServiceAccounts(ns).CreateToken(ctx, sa, &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{ExpirationSeconds: int64p(1800)},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	env.AddMarker("token of "+ns+"/"+sa, tr.Status.Token)
	return tr.Status.Token, nil
}

func clientWithToken(env *audit.Env, token string) (*kubernetes.Clientset, error) {
	cfg := env.ConfigFor(func(c *rest.Config) {
		c.TLSClientConfig.CertData, c.TLSClientConfig.KeyData = nil, nil
		c.TLSClientConfig.CertFile, c.TLSClientConfig.KeyFile = "", ""
		c.BearerToken = token
		c.BearerTokenFile = ""
	})
	return kubernetes.NewForConfig(cfg)
}

// clientAs authenticates with the given bearer token and, if impUser is set,
// impersonates that user (and impGroups). This reproduces the exact request
// shape of a proxy such as the authenticating proxy: the audit event records
// user = the token's identity and impersonatedUser = the impersonated one.
func clientAs(env *audit.Env, token, impUser string, impGroups []string) (*kubernetes.Clientset, error) {
	cfg := env.ConfigFor(func(c *rest.Config) {
		c.TLSClientConfig.CertData, c.TLSClientConfig.KeyData = nil, nil
		c.TLSClientConfig.CertFile, c.TLSClientConfig.KeyFile = "", ""
		c.BearerToken = token
		c.BearerTokenFile = ""
		if impUser != "" {
			c.Impersonate = rest.ImpersonationConfig{UserName: impUser, Groups: impGroups}
		}
	})
	return kubernetes.NewForConfig(cfg)
}

func rawGet(ctx context.Context, c kubernetes.Interface, path string) error {
	_, err := c.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
	return err
}

// ---------------------------------------------------------------------------
// The scenarios. Order matters: later scenarios use objects of earlier ones.
// ---------------------------------------------------------------------------

// Scenarios returns the scenarios that apply to this cluster, in the order
// they must run: the core set, then the edge cases, then namespace-delete
// (most scenarios live in the test namespace, so it has to be late), then the
// observations of the teardown it causes.
func Scenarios(env *audit.Env) []Scenario {
	base := baseScenarios()
	last := base[len(base)-1]
	out := append([]Scenario{}, base[:len(base)-1]...)
	out = append(out, EdgeScenarios()...)
	out = append(out, EcosystemScenarios()...)
	out = append(out, last)
	out = append(out, TeardownScenarios()...)

	applicable := make([]Scenario, 0, len(out))
	for _, s := range out {
		if s.Needs == nil || s.Needs(env) {
			applicable = append(applicable, s)
		}
	}
	return applicable
}

// needsProxy and needsCalico gate the scenarios that only make sense when the
// profile says the cluster runs that component.
func needsProxy(env *audit.Env) bool  { return env.Cfg.Component.Proxy.Enabled }
func needsCalico(env *audit.Env) bool { return env.Cfg.Component.Calico.Enabled }

// proxyGroup is the first group the proxy impersonates, used in expectations.
func proxyGroup(env *audit.Env) string {
	if len(env.ProxyGroups) == 0 {
		return ""
	}
	return env.ProxyGroups[0]
}

func baseScenarios() []Scenario {
	return []Scenario{
		// ------------------------------------------------------------------
		// Namespace and workloads
		// ------------------------------------------------------------------
		{
			Name: "namespace-create",
			Act: func(ctx context.Context, env *audit.Env) error {
				_, err := env.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: env.Namespace, Labels: map[string]string{"audit-test": env.RunID}},
				}, metav1.CreateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "namespace create is logged with body", Requirement: ReqResources,
					Match: audit.Match{Verb: "create", Resource: "namespaces", Name: env.Namespace},
					Level: "Request", RequestBody: audit.Required, RequestBodyLacks: []string{"managedFields"},
				}}
			},
		},
		{
			Name: "pod-create-plain",
			Act: func(ctx context.Context, env *audit.Env) error {
				_, err := env.Client.CoreV1().Pods(env.Namespace).Create(ctx, sleepPod(podPlain, env.Image, map[string]string{"audit-test": "plain"}), metav1.CreateOptions{})
				if err != nil {
					return err
				}
				_, err = waitPodRunning(ctx, env.Client, env.Namespace, podPlain, 3*time.Minute)
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "pod create is logged at RequestResponse with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: podPlain},
						Level: "RequestResponse", RequestBody: audit.Required, RequestBodyContains: []string{env.Image},
					},
					{
						Desc: "pod get by a human is logged", Requirement: ReqHumans,
						Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: podPlain},
						Level: "RequestResponse", RequestBody: audit.Forbidden,
					},
					{
						Desc: "scheduler binding is Metadata only", Requirement: ReqNoise,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "binding", Namespace: env.Namespace, Name: podPlain, AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, Gap: gapNoise,
					},
					{
						Desc: "kubelet pods/status updates are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "pods", Subresource: "status", Namespace: env.Namespace, UserGroup: "system:nodes", AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},
		{
			Name: "pod-create-privileged",
			Act: func(ctx context.Context, env *audit.Env) error {
				p := sleepPod(podPrivileged, env.Image, map[string]string{"audit-test": "privileged"})
				p.Spec.HostPID = true
				p.Spec.HostNetwork = true
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				p.Spec.Volumes = []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/hostname"}}}}
				p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "host", MountPath: "/host-hostname"}}
				_, err := env.Client.CoreV1().Pods(env.Namespace).Create(ctx, p, metav1.CreateOptions{})
				return ignoreForbidden(err)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "privileged/hostPID/hostNetwork/hostPath pod body is visible", Requirement: ReqPrivileged,
					Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: podPrivileged},
					Level: "RequestResponse", RequestBody: audit.Required,
					RequestBodyContains: []string{`"privileged":true`, `"hostPID":true`, `"hostNetwork":true`, `"hostPath"`},
				}}
			},
		},
		{
			Name: "deployment-lifecycle",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.AppsV1().Deployments(env.Namespace)
				labels := map[string]string{"app": deployName}
				pod := sleepPod("", env.Image, labels)
				_, err := c.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: deployName},
					Spec: appsv1.DeploymentSpec{
						Replicas: int32p(1),
						Selector: &metav1.LabelSelector{MatchLabels: labels},
						Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: pod.Spec},
					},
				}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				if _, err := c.Patch(ctx, deployName, types.StrategicMergePatchType, []byte(`{"metadata":{"labels":{"audit-test":"patched"}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					sc, err := c.GetScale(ctx, deployName, metav1.GetOptions{})
					if err != nil {
						return err
					}
					sc.Spec.Replicas = 2
					_, err = c.UpdateScale(ctx, deployName, sc, metav1.UpdateOptions{})
					return err
				}); err != nil {
					return err
				}
				// Wait until the controllers created pods for the deployment.
				deadline := time.Now().Add(60 * time.Second)
				for {
					pods, err := env.Client.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + deployName})
					if err != nil {
						return err
					}
					if len(pods.Items) >= 2 || time.Now().After(deadline) {
						break
					}
					time.Sleep(2 * time.Second)
				}
				return c.Delete(ctx, deployName, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "deployment create with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Resource: "deployments", Subresource: "-", Namespace: env.Namespace, Name: deployName},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{env.Image}, Gap: gapNonCoreBody,
					},
					{
						Desc: "deployment patch with patch body", Requirement: ReqResources,
						Match: audit.Match{Verb: "patch", Resource: "deployments", Subresource: "-", Namespace: env.Namespace, Name: deployName},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"audit-test":"patched"`}, Gap: gapNonCoreBody,
					},
					{
						Desc: "deployment scale with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "update", Resource: "deployments", Subresource: "scale", Namespace: env.Namespace, Name: deployName},
						Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody,
					},
					{
						Desc: "deployment delete", Requirement: ReqResources,
						Match: audit.Match{Verb: "delete", Resource: "deployments", Subresource: "-", Namespace: env.Namespace, Name: deployName},
						Level: "Metadata",
					},
					{
						Desc: "replicaset created by deployment-controller is Metadata", Requirement: ReqNoise,
						Match: audit.Match{Verb: "create", Resource: "replicasets", Namespace: env.Namespace, NamePrefix: deployName, UserGroup: "system:serviceaccounts:kube-system", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
					{
						Desc: "pods created by replicaset-controller are Metadata", Requirement: ReqNoise,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, User: "system:serviceaccount:kube-system:replicaset-controller", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, Gap: gapNoise,
					},
					{
						Desc: "deployment-controller status updates are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "deployments", Subresource: "status", Namespace: env.Namespace, AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},
		{
			Name: "pods-deletecollection",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().Pods(env.Namespace)
				if _, err := c.Create(ctx, sleepPod(podDelColl, env.Image, map[string]string{"audit-test": "delcoll"}), metav1.CreateOptions{}); err != nil {
					return err
				}
				return c.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "audit-test=delcoll"})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "pods deletecollection is logged", Requirement: ReqResources,
					Match: audit.Match{Verb: "deletecollection", Resource: "pods", Namespace: env.Namespace},
					Level: "RequestResponse",
				}}
			},
		},
		{
			Name: "pod-eviction",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().Pods(env.Namespace)
				if _, err := c.Create(ctx, sleepPod(podEvict, env.Image, nil), metav1.CreateOptions{}); err != nil {
					return err
				}
				return c.EvictV1(ctx, &policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: podEvict, Namespace: env.Namespace}})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "pod eviction (kubectl drain) is logged with body", Requirement: ReqResources,
					Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "eviction", Namespace: env.Namespace, Name: podEvict},
					Level: "Request", RequestBody: audit.Required,
				}}
			},
		},
		{
			Name: "service-ingress-pvc-networkpolicy",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				if _, err := env.Client.CoreV1().Services(ns).Create(ctx, &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-svc"},
					Spec: corev1.ServiceSpec{
						Selector: map[string]string{"audit-test": "plain"},
						Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				pt := networkingv1.PathTypePrefix
				if _, err := env.Client.NetworkingV1().Ingresses(ns).Create(ctx, &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-ingress"},
					Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
						Host: "audit-" + env.RunID + ".example.invalid",
						IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
							Path: "/", PathType: &pt,
							Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "audit-svc", Port: networkingv1.ServiceBackendPort{Number: 80}}},
						}}}},
					}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// storageClassName "" prevents dynamic provisioning: the claim stays Pending.
				emptySC := ""
				if _, err := env.Client.CoreV1().PersistentVolumeClaims(ns).Create(ctx, &corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-pvc"},
					Spec: corev1.PersistentVolumeClaimSpec{
						StorageClassName: &emptySC,
						AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				_, err := env.Client.NetworkingV1().NetworkPolicies(ns).Create(ctx, &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-np"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"audit-test": "nothing"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					},
				}, metav1.CreateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "service create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "services", Namespace: ns, Name: "audit-svc"}, Level: "Request", RequestBody: audit.Required},
					{Desc: "ingress create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "ingresses", Namespace: ns, Name: "audit-ingress"}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "persistentvolumeclaim create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "persistentvolumeclaims", Namespace: ns, Name: "audit-pvc"}, Level: "Request", RequestBody: audit.Required},
					{Desc: "networkpolicy create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "networkpolicies", Group: "networking.k8s.io", Namespace: ns, Name: "audit-np"}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{
						Desc: "ingress-nginx / cert-manager status updates are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "ingresses", Subresource: "status", Namespace: ns, AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},
		{
			Name: "quota-limitrange-pdb",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				if _, err := env.Client.CoreV1().ResourceQuotas(ns).Create(ctx, &corev1.ResourceQuota{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-quota"},
					Spec:       corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{corev1.ResourcePods: resource.MustParse("100")}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().LimitRanges(ns).Create(ctx, &corev1.LimitRange{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-limits"},
					// Default/DefaultRequest are set explicitly: without them the
					// LimitRanger uses Max as the default limit (and request), which
					// makes every later pod in the namespace unschedulable.
					Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
						Type:           corev1.LimitTypeContainer,
						Max:            corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Gi")},
						Default:        corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
						DefaultRequest: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("16Mi")},
					}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				minAvail := intstr.FromInt32(0)
				_, err := env.Client.PolicyV1().PodDisruptionBudgets(ns).Create(ctx, &policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-pdb"},
					Spec: policyv1.PodDisruptionBudgetSpec{
						MinAvailable: &minAvail,
						Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"audit-test": "nothing"}},
					},
				}, metav1.CreateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "resourcequota create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "resourcequotas", Namespace: ns}, Level: "Request", RequestBody: audit.Required},
					{Desc: "limitrange create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "limitranges", Namespace: ns}, Level: "Request", RequestBody: audit.Required},
					{Desc: "poddisruptionbudget create", Requirement: ReqResources, Match: audit.Match{Verb: "create", Resource: "poddisruptionbudgets", Namespace: ns}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{
						Desc: "resourcequota status updates (quota admission runs as system:apiserver) are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "resourcequotas", Subresource: "status", Namespace: ns, AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},

		// ------------------------------------------------------------------
		// Secrets and configmaps
		// ------------------------------------------------------------------
		{
			Name: "secret-lifecycle",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().Secrets(env.Namespace)
				value := "SUPERSECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("secret value", value)
				env.AddMarker("secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value)))
				s, err := c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: secretName},
					StringData: map[string]string{"password": value},
				}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				if _, err := c.Get(ctx, secretName, metav1.GetOptions{}); err != nil {
					return err
				}
				if _, err := c.List(ctx, metav1.ListOptions{}); err != nil {
					return err
				}
				w, err := c.Watch(ctx, metav1.ListOptions{TimeoutSeconds: int64p(2)})
				if err != nil {
					return err
				}
				for range w.ResultChan() {
				}
				value2 := "SUPERSECRET2-" + env.RunID + "-do-not-log"
				env.AddMarker("updated secret value", value2)
				env.AddMarker("updated secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value2)))
				s.StringData = map[string]string{"password": value2}
				if _, err := c.Update(ctx, s, metav1.UpdateOptions{}); err != nil {
					return err
				}
				if _, err := c.Patch(ctx, secretName, types.MergePatchType, []byte(`{"metadata":{"labels":{"audit-test":"patched"}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				return c.Delete(ctx, secretName, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				m := func(verb string) audit.Match {
					return audit.Match{Verb: verb, Resource: "secrets", Namespace: env.Namespace}
				}
				var out []audit.Expect
				for _, verb := range []string{"create", "get", "list", "update", "patch", "delete"} {
					out = append(out, audit.Expect{
						Desc: "secret " + verb + " logged at Metadata without body", Requirement: ReqSecrets,
						Match: m(verb), Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					})
				}
				out = append(out, audit.Expect{
					Desc: "secret watch logged at Metadata, both stages (long-running)", Requirement: ReqSecrets,
					Match: m("watch"), Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					Stages: []string{"ResponseStarted", "ResponseComplete"},
				})
				return out
			},
		},
		{
			Name: "configmap-namespaced",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().ConfigMaps(env.Namespace)
				value := "CONFIGMAP-CRED-" + env.RunID
				env.AddMarker("configmap value", value)
				cm, err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "audit-cm"}, Data: map[string]string{"cred": value}}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				cm.Data["cred"] = value + "-2"
				if _, err := c.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
					return err
				}
				if _, err := c.Get(ctx, "audit-cm", metav1.GetOptions{}); err != nil {
					return err
				}
				return c.Delete(ctx, "audit-cm", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				var out []audit.Expect
				for _, verb := range []string{"create", "update", "delete"} {
					out = append(out, audit.Expect{
						Desc: "configmap " + verb + " outside kube-system logged without body", Requirement: ReqResources,
						Match: audit.Match{Verb: verb, Resource: "configmaps", Namespace: env.Namespace, Name: "audit-cm"},
						Level: "Metadata", RequestBody: audit.Forbidden,
					})
				}
				out = append(out, audit.Expect{
					Desc: "configmap get by a human is logged", Requirement: ReqHumans,
					Match: audit.Match{Verb: "get", Resource: "configmaps", Namespace: env.Namespace, Name: "audit-cm"},
					Level: "Metadata",
				})
				return out
			},
		},
		{
			Name: "configmap-kube-system",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().ConfigMaps("kube-system")
				name := env.Name("cm")
				if _, err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: map[string]string{"setting": "audit-visible-" + env.RunID}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := c.Patch(ctx, name, types.MergePatchType, []byte(`{"data":{"setting":"audit-changed-`+env.RunID+`"}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				return c.Delete(ctx, name, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("cm")
				return []audit.Expect{
					{
						Desc: "kube-system configmap create logged with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: "kube-system", Name: name},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-visible-" + env.RunID},
					},
					{
						Desc: "kube-system configmap patch logged with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "patch", Resource: "configmaps", Namespace: "kube-system", Name: name},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-changed-" + env.RunID},
					},
					{
						Desc: "kube-system configmap delete logged", Requirement: ReqResources,
						Match: audit.Match{Verb: "delete", Resource: "configmaps", Namespace: "kube-system", Name: name},
						Level: "Request",
					},
				}
			},
		},

		// ------------------------------------------------------------------
		// RBAC and service accounts
		// ------------------------------------------------------------------
		{
			Name: "rbac-lifecycle",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				rb := env.Client.RbacV1()
				for _, sa := range []string{saRestricted, saWorker} {
					if _, err := env.Client.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa}}, metav1.CreateOptions{}); err != nil {
						return err
					}
				}
				role, err := rb.Roles(ns).Create(ctx, &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-worker"},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
				}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				role.Rules[0].Verbs = []string{"get", "list", "create", "delete"}
				if _, err := rb.Roles(ns).Update(ctx, role, metav1.UpdateOptions{}); err != nil {
					return err
				}
				if _, err := rb.RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-worker"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saWorker, Namespace: ns}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "audit-worker"},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				crName := env.Name("cr")
				if _, err := rb.ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: crName},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"list"}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := rb.ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: crName},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "audit-nobody-" + env.RunID, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: crName},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := rb.ClusterRoleBindings().Delete(ctx, crName, metav1.DeleteOptions{}); err != nil {
					return err
				}
				return rb.ClusterRoles().Delete(ctx, crName, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				crName := env.Name("cr")
				g := "rbac.authorization.k8s.io"
				return []audit.Expect{
					{Desc: "serviceaccount create", Requirement: ReqTokens, Match: audit.Match{Verb: "create", Resource: "serviceaccounts", Subresource: "-", Namespace: ns, Name: saRestricted}, Level: "Request", RequestBody: audit.Required},
					{Desc: "role create", Requirement: ReqRBAC, Match: audit.Match{Verb: "create", Group: g, Resource: "roles", Namespace: ns}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "role update", Requirement: ReqRBAC, Match: audit.Match{Verb: "update", Group: g, Resource: "roles", Namespace: ns}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"create"`}, Gap: gapNonCoreBody},
					{Desc: "rolebinding create", Requirement: ReqRBAC, Match: audit.Match{Verb: "create", Group: g, Resource: "rolebindings", Namespace: ns, Name: "audit-worker"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{saWorker}, Gap: gapNonCoreBody},
					{Desc: "clusterrole create", Requirement: ReqRBAC, Match: audit.Match{Verb: "create", Group: g, Resource: "clusterroles", Name: crName}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "clusterrolebinding create", Requirement: ReqRBAC, Match: audit.Match{Verb: "create", Group: g, Resource: "clusterrolebindings", Name: crName}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "role and rolebinding writes are logged (any level)", Requirement: ReqRBAC, Match: audit.Match{Verbs: []string{"create", "update"}, Group: g, Resources: []string{"roles", "rolebindings"}, Namespace: ns, Name: "audit-worker"}, MinEvents: 3},
					{Desc: "clusterrolebinding delete", Requirement: ReqRBAC, Match: audit.Match{Verb: "delete", Group: g, Resource: "clusterrolebindings", Name: crName}, Level: "Metadata"},
					{Desc: "clusterrole delete", Requirement: ReqRBAC, Match: audit.Match{Verb: "delete", Group: g, Resource: "clusterroles", Name: crName}, Level: "Metadata"},
				}
			},
		},
		{
			Name: "serviceaccount-token-issuance",
			Act: func(ctx context.Context, env *audit.Env) error {
				_, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "TokenRequest logged at Request; the token lives in the response, which is not recorded", Requirement: ReqTokens,
					Match: audit.Match{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: env.Namespace, Name: saRestricted},
					Level: "Request", RequestBody: audit.Required, ResponseBody: audit.Forbidden,
				}}
			},
		},
		{
			Name: "csr-issuance",
			Act: func(ctx context.Context, env *audit.Env) error {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return err
				}
				cn := "audit-csr-user-" + env.RunID
				der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn, Organization: []string{"audit-test"}}}, key)
				if err != nil {
					return err
				}
				c := env.Client.CertificatesV1().CertificateSigningRequests()
				name := env.Name("csr")
				csr, err := c.Create(ctx, &certv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: certv1.CertificateSigningRequestSpec{
						Request:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
						SignerName:        "kubernetes.io/kube-apiserver-client",
						Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
						ExpirationSeconds: int32p(600),
					},
				}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
					Type: certv1.CertificateApproved, Status: corev1.ConditionTrue, Reason: "AuditPolicyTest", Message: "approved by audit policy test",
				})
				if _, err := c.UpdateApproval(ctx, name, csr, metav1.UpdateOptions{}); err != nil {
					return err
				}
				var certPEM []byte
				deadline := time.Now().Add(20 * time.Second)
				for len(certPEM) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Second)
					cur, err := c.Get(ctx, name, metav1.GetOptions{})
					if err != nil {
						return err
					}
					certPEM = cur.Status.Certificate
				}
				if err := c.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				if len(certPEM) == 0 {
					// No in-cluster signer for kubernetes.io/kube-apiserver-client:
					// many clusters sign client certificates with an external CA,
					// so the CSR is approved but never issued. The dependent
					// scenario csr-cert-user-denied is then skipped.
					return nil
				}
				keyDER, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					return err
				}
				env.IssuedCert = certPEM
				env.IssuedKey = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("csr")
				g := "certificates.k8s.io"
				return []audit.Expect{
					{Desc: "CSR create logged with body", Requirement: ReqTokens, Match: audit.Match{Verb: "create", Group: g, Resource: "certificatesigningrequests", Subresource: "-", Name: name}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "CSR approval logged with body", Requirement: ReqTokens, Match: audit.Match{Verb: "update", Group: g, Resource: "certificatesigningrequests", Subresource: "approval", Name: name}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"AuditPolicyTest"}, Gap: gapNonCoreBody},
					{Desc: "CSR create and approval are logged (any level)", Requirement: ReqTokens, Match: audit.Match{Verbs: []string{"create", "update"}, Group: g, Resource: "certificatesigningrequests", Name: name}, MinEvents: 2},
					{Desc: "CSR delete logged", Requirement: ReqTokens, Match: audit.Match{Verb: "delete", Group: g, Resource: "certificatesigningrequests", Name: name}, Level: "Metadata"},
					{
						Desc: "CSR signing (status update by certificate-controller) is dropped by design", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Group: g, Resource: "certificatesigningrequests", Subresource: "status", Name: name, AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},
		{
			Name:     "csr-cert-user-denied",
			Optional: true,
			Act: func(ctx context.Context, env *audit.Env) error {
				if len(env.IssuedCert) == 0 {
					return fmt.Errorf("no certificate was issued for the test CSR (no in-cluster signer)")
				}
				// A human-like user with a valid certificate but no RBAC.
				cfg := env.ConfigFor(func(cfg *rest.Config) {
					cfg.TLSClientConfig.CertFile, cfg.TLSClientConfig.KeyFile = "", ""
					cfg.TLSClientConfig.CertData = env.IssuedCert
					cfg.TLSClientConfig.KeyData = env.IssuedKey
				})
				cl, err := kubernetes.NewForConfig(cfg)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Secrets(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for csr user listing secrets, got %v", err)
				}
				_, err = cl.CoreV1().Pods(env.Namespace).Create(ctx, sleepPod("csr-user-pod", env.Image, nil), metav1.CreateOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for csr user creating pod, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				cn := "audit-csr-user-" + env.RunID
				forbid := map[string]string{"authorization.k8s.io/decision": "forbid"}
				return []audit.Expect{
					{Desc: "denied secret list by cert user is logged", Requirement: ReqAuthFail, Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: env.Namespace, User: cn}, Level: "Metadata", Code: 403, Annotations: forbid},
					{Desc: "denied pod create by cert user is logged", Requirement: ReqAuthFail, Match: audit.Match{Verb: "create", Resource: "pods", Namespace: env.Namespace, User: cn}, Level: "RequestResponse", Code: 403, Annotations: forbid},
				}
			},
		},

		// ------------------------------------------------------------------
		// Interactive access to containers and nodes
		// ------------------------------------------------------------------
		{
			Name: "pod-exec-attach-portforward",
			Act: func(ctx context.Context, env *audit.Env) error {
				cfg := env.ConfigFor(nil)
				rc := env.Client.CoreV1().RESTClient()
				marker := "audit-exec-" + env.RunID
				execReq := func() *rest.Request {
					return rc.Post().Resource("pods").Namespace(env.Namespace).Name(podPlain).SubResource("exec").
						VersionedParams(&corev1.PodExecOptions{Command: []string{"echo", marker}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
				}
				// SPDY exec (POST)
				ex, err := remotecommand.NewSPDYExecutor(cfg, "POST", execReq().URL())
				if err != nil {
					return err
				}
				if err := ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
					return fmt.Errorf("spdy exec: %w", err)
				}
				// WebSocket exec (GET, what recent kubectl uses)
				wsReq := rc.Get().Resource("pods").Namespace(env.Namespace).Name(podPlain).SubResource("exec").
					VersionedParams(&corev1.PodExecOptions{Command: []string{"echo", marker + "-ws"}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
				wex, err := remotecommand.NewWebSocketExecutor(cfg, "GET", wsReq.URL().String())
				if err != nil {
					return err
				}
				if err := wex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
					return fmt.Errorf("websocket exec: %w", err)
				}
				// attach (stays open until the container exits; cut it after 3s)
				attReq := rc.Post().Resource("pods").Namespace(env.Namespace).Name(podPlain).SubResource("attach").
					VersionedParams(&corev1.PodAttachOptions{Stdout: true, Stderr: true}, scheme.ParameterCodec)
				att, err := remotecommand.NewSPDYExecutor(cfg, "POST", attReq.URL())
				if err != nil {
					return err
				}
				actx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_ = att.StreamWithContext(actx, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard})
				cancel()
				// port-forward
				transport, upgrader, err := spdy.RoundTripperFor(cfg)
				if err != nil {
					return err
				}
				pfReq := rc.Post().Resource("pods").Namespace(env.Namespace).Name(podPlain).SubResource("portforward")
				dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", pfReq.URL())
				stop, ready := make(chan struct{}), make(chan struct{})
				pf, err := portforward.New(dialer, []string{"0:8080"}, stop, ready, io.Discard, io.Discard)
				if err != nil {
					return err
				}
				pfErr := make(chan error, 1)
				go func() { pfErr <- pf.ForwardPorts() }()
				select {
				case <-ready:
				case err := <-pfErr:
					return fmt.Errorf("portforward: %w", err)
				case <-time.After(15 * time.Second):
					return fmt.Errorf("portforward not ready after 15s")
				}
				close(stop)
				// logs
				if _, err := env.Client.CoreV1().Pods(env.Namespace).GetLogs(podPlain, &corev1.PodLogOptions{}).DoRaw(ctx); err != nil {
					return fmt.Errorf("logs: %w", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "SPDY exec logged with command in URI, both stages", Requirement: ReqExec,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: ns, Name: podPlain},
						Level: "Request", Stages: []string{"ResponseStarted", "ResponseComplete"},
						// requestURI carries the executed command as query parameters
					},
					{
						Desc: "WebSocket exec (verb get) is logged", Requirement: ReqExec,
						Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "exec", Namespace: ns, Name: podPlain},
						Level: "Request",
					},
					{Desc: "attach is logged", Requirement: ReqExec, Match: audit.Match{Resource: "pods", Subresource: "attach", Namespace: ns, Name: podPlain}, Level: "Request"},
					{Desc: "portforward is logged", Requirement: ReqExec, Match: audit.Match{Resource: "pods", Subresource: "portforward", Namespace: ns, Name: podPlain}, Level: "Request"},
					{Desc: "pod log read is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "log", Namespace: ns, Name: podPlain}, Level: "Metadata"},
				}
			},
		},
		{
			Name: "pod-ephemeral-container",
			Act: func(ctx context.Context, env *audit.Env) error {
				c := env.Client.CoreV1().Pods(env.Namespace)
				p, err := c.Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debugger", Image: env.Image, Command: []string{"sh", "-c", "sleep 60"}},
				})
				_, err = c.UpdateEphemeralContainers(ctx, podPlain, p, metav1.UpdateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "kubectl debug (ephemeralcontainers) logged with body", Requirement: ReqExec,
					Match: audit.Match{Verb: "update", Resource: "pods", Subresource: "ephemeralcontainers", Namespace: env.Namespace, Name: podPlain},
					Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"debugger"},
				}}
			},
		},
		{
			Name: "proxy-subresources",
			Act: func(ctx context.Context, env *audit.Env) error {
				rc := env.Client.CoreV1().RESTClient()
				p, err := env.Client.CoreV1().Pods(env.Namespace).Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				// The pod and service do not serve HTTP; the proxy request fails
				// after the apiserver has accepted (and audited) it.
				_, _ = rc.Get().Namespace(env.Namespace).Resource("pods").Name(podPlain).SubResource("proxy").Suffix("/").DoRaw(ctx)
				_, _ = rc.Get().Namespace(env.Namespace).Resource("services").Name("audit-svc").SubResource("proxy").Suffix("/").DoRaw(ctx)
				if _, err := rc.Get().Resource("nodes").Name(p.Spec.NodeName).SubResource("proxy").Suffix("healthz").DoRaw(ctx); err != nil {
					return fmt.Errorf("nodes/proxy healthz: %w", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "pods/proxy is logged", Requirement: ReqExec, Match: audit.Match{Resource: "pods", Subresource: "proxy", Namespace: ns, Name: podPlain}, Level: "Request"},
					{Desc: "services/proxy is logged", Requirement: ReqExec, Match: audit.Match{Resource: "services", Subresource: "proxy", Namespace: ns}, Level: "Request"},
					{Desc: "nodes/proxy is logged", Requirement: ReqExec, Match: audit.Match{Resource: "nodes", Subresource: "proxy"}, Level: "Request"},
				}
			},
		},

		// ------------------------------------------------------------------
		// Impersonation, authn and authz failures, anonymous access
		// ------------------------------------------------------------------
		{
			Name: "impersonation",
			Act: func(ctx context.Context, env *audit.Env) error {
				asUser, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{UserName: "audit-impersonated-" + env.RunID, Groups: []string{"audit-impersonated-group"}}
				}))
				if err != nil {
					return err
				}
				if _, err := asUser.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for impersonated user, got %v", err)
				}
				// Impersonating a kube-system service account: the policy must
				// match on the real (human) user, not on the impersonated groups
				// whose reads are dropped.
				asSA, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:default"}
				}))
				if err != nil {
					return err
				}
				_, err = asSA.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{})
				return ignoreForbidden(err)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "request with --as/--as-group carries impersonatedUser", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, User: env.AdminUser, ImpersonatedUser: "audit-impersonated-" + env.RunID},
						Level: "RequestResponse", Impersonated: "audit-impersonated-" + env.RunID, Code: 403,
					},
					{
						Desc: "impersonating a kube-system SA is still logged (policy matches the real user)", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, User: env.AdminUser, ImpersonatedUser: "system:serviceaccount:kube-system:default"},
						Level: "RequestResponse", Impersonated: "system:serviceaccount:kube-system:default",
					},
				}
			},
		},
		{
			Name: "authz-failure-unprivileged-sa",
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Secrets(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 listing secrets, got %v", err)
				}
				if _, err := cl.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 listing pods, got %v", err)
				}
				if _, err := cl.CoreV1().ConfigMaps(env.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "denied-cm"}}, metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 creating configmap, got %v", err)
				}
				if _, err := cl.CoreV1().Pods(env.Namespace).Create(ctx, sleepPod("denied-pod", env.Image, nil), metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 creating pod, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:" + env.Namespace + ":" + saRestricted
				forbid := map[string]string{"authorization.k8s.io/decision": "forbid"}
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "denied secret list by unprivileged SA", Requirement: ReqAuthFail, Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: ns, User: user}, Level: "Metadata", Code: 403, Annotations: forbid},
					{Desc: "denied pod list by unprivileged SA", Requirement: ReqAuthFail, Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, User: user}, Level: "RequestResponse", Code: 403, Annotations: forbid},
					{Desc: "denied configmap create by unprivileged SA", Requirement: ReqAuthFail, Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: ns, User: user}, Level: "Metadata", Code: 403, Annotations: forbid},
					{Desc: "denied pod create by unprivileged SA", Requirement: ReqAuthFail, Match: audit.Match{Verb: "create", Resource: "pods", Namespace: ns, User: user}, Level: "RequestResponse", Code: 403, Annotations: forbid},
				}
			},
		},
		{
			Name: "workload-sa-privileged-pod",
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.Namespace, saWorker)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				p := sleepPod(podWorkerPriv, env.Image, nil)
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				if _, err := cl.CoreV1().Pods(env.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return err
				}
				return cl.CoreV1().Pods(env.Namespace).Delete(ctx, podWorkerPriv, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:" + env.Namespace + ":" + saWorker
				return []audit.Expect{
					{
						Desc: "privileged pod created by a unprivileged SA (operator) is logged with body", Requirement: ReqPrivileged,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: podWorkerPriv, User: user},
						Level: "RequestResponse", RequestBody: audit.Required, RequestBodyContains: []string{`"privileged":true`},
					},
					{
						Desc: "pod delete by a unprivileged SA is logged", Requirement: ReqResources,
						Match: audit.Match{Verb: "delete", Resource: "pods", Namespace: env.Namespace, Name: podWorkerPriv, User: user},
						Level: "RequestResponse",
					},
				}
			},
		},
		{
			Name: "kube-system-sa-denied",
			Act: func(ctx context.Context, env *audit.Env) error {
				name := env.Name("sa")
				if _, err := env.Client.CoreV1().ServiceAccounts("kube-system").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, "kube-system", name)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				_, err = cl.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403, got %v", err)
				}
				_, err = cl.CoreV1().Secrets(env.Namespace).List(ctx, metav1.ListOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403, got %v", err)
				}
				p := sleepPod("ks-sa-pod", env.Image, nil)
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				_, err = cl.CoreV1().Pods(env.Namespace).Create(ctx, p, metav1.CreateOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403, got %v", err)
				}
				return env.Client.CoreV1().ServiceAccounts("kube-system").Delete(ctx, name, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:kube-system:" + env.Name("sa")
				forbid := map[string]string{"authorization.k8s.io/decision": "forbid"}
				return []audit.Expect{
					{
						Desc: "denied pod list by a kube-system SA (e.g. stolen token)", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, User: user},
						Level: "RequestResponse", Code: 403, Annotations: forbid,
					},
					{
						Desc: "denied secret list by a kube-system SA is logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: env.Namespace, User: user},
						Level: "Metadata", Code: 403, Annotations: forbid,
					},
					{
						Desc: "denied pod create by a kube-system SA is logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "create", Resource: "pods", Namespace: env.Namespace, User: user},
						Level: "RequestResponse", Code: 403, Annotations: forbid,
					},
					{
						Desc: "kube-system SA create is logged with body", Requirement: ReqTokens,
						Match: audit.Match{Verb: "create", Resource: "serviceaccounts", Subresource: "-", Namespace: "kube-system", Name: env.Name("sa")},
						Level: "Request", RequestBody: audit.Required,
					},
				}
			},
		},
		{
			Name: "authn-failure",
			Act: func(ctx context.Context, env *audit.Env) error {
				cl, err := clientWithToken(env, "audit-invalid-token-"+env.RunID)
				if err != nil {
					return err
				}
				if _, err = cl.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsUnauthorized(err) {
					return fmt.Errorf("expected 401, got %v", err)
				}
				if _, err = cl.CoreV1().Secrets(env.Namespace).List(ctx, metav1.ListOptions{}); !apierrors.IsUnauthorized(err) {
					return fmt.Errorf("expected 401, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						// Failed authentication is audited at stage ResponseStarted only.
						Desc: "invalid bearer token (401) is logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, ResponseCode: 401},
						Level: "RequestResponse", Code: 401, UsernameEmpty: true, Stages: []string{"ResponseStarted"},
					},
					{
						Desc: "invalid bearer token (401) against secrets is logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: env.Namespace, ResponseCode: 401},
						Level: "Metadata", Code: 401, UsernameEmpty: true, Stages: []string{"ResponseStarted"},
					},
				}
			},
		},
		{
			Name: "anonymous",
			Act: func(ctx context.Context, env *audit.Env) error {
				cl, err := kubernetes.NewForConfig(env.AnonymousConfig())
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Secrets(env.Namespace).List(ctx, metav1.ListOptions{}); err == nil {
					return fmt.Errorf("anonymous secret list succeeded")
				}
				for _, p := range []string{"/api", "/apis", "/healthz", "/livez", "/readyz", "/version", "/"} {
					_ = rawGet(ctx, cl, p)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				anon := audit.Match{User: "system:anonymous", NonResource: true}
				uri := func(u string) audit.Match { m := anon; m.URIPrefix = u; return m }
				return []audit.Expect{
					{Desc: "anonymous secret list is logged", Requirement: ReqAnonymous, Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: env.Namespace, User: "system:anonymous"}, Level: "Metadata"},
					{Desc: "anonymous /api discovery is logged", Requirement: ReqAnonymous, Match: uri("/api"), Level: "Metadata"},
					{Desc: "anonymous /healthz is dropped", Requirement: ReqNoise, Match: uri("/healthz"), Level: "None", Gap: gapNoise},
					{Desc: "anonymous /livez is dropped", Requirement: ReqNoise, Match: uri("/livez"), Level: "None", Gap: gapNoise},
					{Desc: "anonymous /readyz is dropped", Requirement: ReqNoise, Match: uri("/readyz"), Level: "None", Gap: gapNoise},
					{Desc: "anonymous /version is logged (the discovery drop covers system:authenticated only)", Requirement: ReqAnonymous, Match: uri("/version"), Level: "Metadata"},
					{Desc: "anonymous GET / (load balancer probe) is dropped", Requirement: ReqNoise, Match: audit.Match{User: "system:anonymous", NonResource: true, URI: "/", Verb: "get"}, Level: "None", Gap: gapNoise},
				}
			},
		},
		{
			Name: "nonresource-authenticated",
			Act: func(ctx context.Context, env *audit.Env) error {
				for _, p := range []string{"/api", "/apis", "/openapi/v2", "/version", "/livez", "/metrics", "/"} {
					if err := rawGet(ctx, env.Client, p); err != nil {
						return fmt.Errorf("GET %s: %w", p, err)
					}
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				me := audit.Match{User: env.AdminUser, NonResource: true}
				uri := func(u string) audit.Match { m := me; m.URIPrefix = u; return m }
				return []audit.Expect{
					{Desc: "authenticated /api discovery is dropped", Requirement: ReqNoise, Match: uri("/api"), Level: "None"},
					{Desc: "authenticated /openapi is dropped", Requirement: ReqNoise, Match: uri("/openapi"), Level: "None", Gap: gapNoise},
					{Desc: "authenticated /version is dropped", Requirement: ReqNoise, Match: uri("/version"), Level: "None"},
					{Desc: "authenticated /livez is dropped", Requirement: ReqNoise, Match: uri("/livez"), Level: "None", Gap: gapNoise},
					{Desc: "authenticated /metrics is logged", Requirement: ReqHumans, Match: uri("/metrics"), Level: "Metadata"},
				}
			},
		},

		// ------------------------------------------------------------------
		// Cluster-scoped and control-plane objects
		// ------------------------------------------------------------------
		{
			Name: "node-label",
			Act: func(ctx context.Context, env *audit.Env) error {
				p, err := env.Client.CoreV1().Pods(env.Namespace).Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				key := env.Label(env.RunID)
				nodes := env.Client.CoreV1().Nodes()
				if _, err := nodes.Patch(ctx, p.Spec.NodeName, types.MergePatchType, []byte(`{"metadata":{"labels":{"`+key+`":"true"}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				_, err = nodes.Patch(ctx, p.Spec.NodeName, types.MergePatchType, []byte(`{"metadata":{"labels":{"`+key+`":null}}}`), metav1.PatchOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "node label change logged with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "patch", Resource: "nodes", Subresource: "-"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{env.Label(env.RunID)},
					},
					{
						Desc: "kubelet nodes/status updates are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "nodes", Subresource: "status", UserGroup: "system:nodes", AnyUA: true},
						Level: "None", Gap: gapNoise,
					},
				}
			},
		},
		{
			Name: "events-and-leases",
			Act: func(ctx context.Context, env *audit.Env) error {
				if _, err := env.Client.CoreV1().Events(env.Namespace).Create(ctx, &corev1.Event{
					ObjectMeta:     metav1.ObjectMeta{Name: "audit-event"},
					InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: env.Namespace, Name: podPlain},
					Reason:         "AuditTest", Message: "audit policy test", Type: "Normal",
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().Events(env.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
					return err
				}
				_, err := env.Client.CoordinationV1().Leases("kube-system").Get(ctx, "kube-controller-manager", metav1.GetOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{Desc: "events are dropped for everyone", Requirement: ReqNoise, Match: audit.Match{Resource: "events", Namespace: env.Namespace}, Level: "None", Gap: gapNoise},
					{Desc: "lease read by a human is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "get", Resource: "leases", Namespace: "kube-system", Name: "kube-controller-manager"}, Level: "Metadata"},
				}
			},
		},
		{
			Name: "cluster-scoped-objects",
			Act: func(ctx context.Context, env *audit.Env) error {
				name := env.Name("obj")
				// StorageClass
				if _, err := env.Client.StorageV1().StorageClasses().Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{Name: name}, Provisioner: env.Label("none"),
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.StorageV1().StorageClasses().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// PriorityClass
				if _, err := env.Client.SchedulingV1().PriorityClasses().Create(ctx, &schedulingv1.PriorityClass{
					ObjectMeta: metav1.ObjectMeta{Name: name}, Value: 1,
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.SchedulingV1().PriorityClasses().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// RuntimeClass
				if _, err := env.Client.NodeV1().RuntimeClasses().Create(ctx, &nodev1.RuntimeClass{
					ObjectMeta: metav1.ObjectMeta{Name: name}, Handler: "audittest",
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.NodeV1().RuntimeClasses().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// PersistentVolume (hostPath, never bound: unique storageClassName)
				if _, err := env.Client.CoreV1().PersistentVolumes().Create(ctx, &corev1.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: corev1.PersistentVolumeSpec{
						Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")},
						AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
						StorageClassName:              name,
						PersistentVolumeSource:        corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/tmp/" + name}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.CoreV1().PersistentVolumes().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// MutatingWebhookConfiguration scoped to a resource that does not exist.
				ignore := admissionv1.Ignore
				none := admissionv1.SideEffectClassNone
				if _, err := env.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, &admissionv1.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Webhooks: []admissionv1.MutatingWebhook{{
						Name:                    env.Domain,
						ClientConfig:            admissionv1.WebhookClientConfig{URL: strPtr("https://127.0.0.1:1/audit-test")},
						FailurePolicy:           &ignore,
						SideEffects:             &none,
						AdmissionReviewVersions: []string{"v1"},
						Rules: []admissionv1.RuleWithOperations{{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule:       admissionv1.Rule{APIGroups: []string{env.Domain}, APIVersions: []string{"v1"}, Resources: []string{"audittests"}},
						}},
					}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// CustomResourceDefinition via the dynamic client
				crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
				crdName := "audittests." + env.Domain
				crd := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
					"metadata": map[string]any{"name": crdName, "labels": map[string]any{"audit-test": env.RunID}},
					"spec": map[string]any{
						"group": env.Domain, "scope": "Namespaced",
						"names": map[string]any{"plural": "audittests", "singular": "audittest", "kind": "AuditTest"},
						"versions": []any{map[string]any{
							"name": "v1", "served": true, "storage": true,
							"schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}},
						}},
					},
				}}
				if _, err := env.Dynamic.Resource(crdGVR).Create(ctx, crd, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Dynamic.Resource(crdGVR).Delete(ctx, crdName, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("obj")
				var out []audit.Expect
				for _, r := range []struct{ group, res, name string }{
					{"storage.k8s.io", "storageclasses", name},
					{"scheduling.k8s.io", "priorityclasses", name},
					{"node.k8s.io", "runtimeclasses", name},
					{"core", "persistentvolumes", name},
					{"admissionregistration.k8s.io", "mutatingwebhookconfigurations", name},
					{"apiextensions.k8s.io", "customresourcedefinitions", "audittests." + env.Domain},
				} {
					create := audit.Expect{Desc: r.res + " create with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: r.group, Resource: r.res, Name: r.name}, Level: "Request", RequestBody: audit.Required}
					del := audit.Expect{Desc: r.res + " delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: r.group, Resource: r.res, Name: r.name}, Level: "Request"}
					if r.group != "core" {
						create.Gap = gapNonCoreBody
						del.Level = "Metadata"
					}
					out = append(out, create, del)
				}
				return out
			},
		},
		{
			Name:     "calico-networkpolicy",
			Optional: true,
			Needs:    needsCalico,
			Act: func(ctx context.Context, env *audit.Env) error {
				gvr := schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "projectcalico.org/v3", "kind": "NetworkPolicy",
					"metadata": map[string]any{"name": "audit-calico-np", "namespace": env.Namespace},
					"spec":     map[string]any{"selector": "audit-test == 'nothing'", "types": []any{"Ingress"}},
				}}
				if _, err := env.Dynamic.Resource(gvr).Namespace(env.Namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Dynamic.Resource(gvr).Namespace(env.Namespace).Delete(ctx, "audit-calico-np", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "calico NetworkPolicy create (aggregated API) logged with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Group: "projectcalico.org", Resource: "networkpolicies", Namespace: env.Namespace},
						Level: "Request", RequestBody: audit.Required,
						Gap: "projectcalico.org is an aggregated API: kube-apiserver only proxies the request and cannot record the body; Request level yields Metadata-like events. Bodies would need an audit policy on calico-apiserver itself.",
					},
					{Desc: "calico NetworkPolicy delete logged", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: "projectcalico.org", Resource: "networkpolicies", Namespace: env.Namespace}, Level: "Metadata"},
					{
						Desc: "calico-apiserver persisting the CRD copy is Metadata only", Requirement: ReqNoise,
						Match: audit.Match{Verb: "create", Group: "crd.projectcalico.org", Resource: "networkpolicies", Namespace: env.Namespace, UserGroup: "system:serviceaccounts:calico-system", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
				}
			},
		},
		{
			Name: "access-reviews",
			Act: func(ctx context.Context, env *audit.Env) error {
				if _, err := env.Client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authzv1.SelfSubjectAccessReview{
					Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{Namespace: env.Namespace, Verb: "delete", Resource: "secrets"}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				_, err := env.Client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:               "system:serviceaccount:" + env.Namespace + ":" + saRestricted,
						ResourceAttributes: &authzv1.ResourceAttributes{Namespace: env.Namespace, Verb: "get", Resource: "secrets"},
					},
				}, metav1.CreateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{Desc: "kubectl auth can-i (SelfSubjectAccessReview) logged with body", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Resource: "selfsubjectaccessreviews"}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "SubjectAccessReview by a human logged with body", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Resource: "subjectaccessreviews"}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
				}
			},
		},
		{
			Name: "watch-pods",
			Act: func(ctx context.Context, env *audit.Env) error {
				w, err := env.Client.CoreV1().Pods(env.Namespace).Watch(ctx, metav1.ListOptions{TimeoutSeconds: int64p(2)})
				if err != nil {
					return err
				}
				for range w.ResultChan() {
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "human watch logged with both stages (long-running)", Requirement: ReqHumans,
					Match: audit.Match{Verb: "watch", Resource: "pods", Namespace: env.Namespace},
					Level: "RequestResponse", Stages: []string{"ResponseStarted", "ResponseComplete"},
				}}
			},
		},

		// ==================================================================
		// the proxy proxied access
		//
		// the proxy's ClusterProxy authenticates to the apiserver as its own
		// service account (system:serviceaccount:<ns>:clusterproxy-*) and
		// impersonates the end-user identity coming from the identity provider.
		// In the audit event, user = the proxy SA and impersonatedUser = the
		// customer. Kubernetes evaluates the AUDIT POLICY against the *real*
		// user (the proxy SA), which these scenarios rely on to check whether
		// the policy still records who the end user was.
		// ==================================================================
		{
			Name:     "authproxy-impersonated-write",
			Optional: true,
			Needs:    needsProxy,
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.ProxySANamespace(), env.ProxySAName())
				if err != nil {
					return fmt.Errorf("mint token for %s/%s (is authenticating proxy installed?): %w", env.ProxySANamespace(), env.ProxySAName(), err)
				}
				cl, err := clientAs(env, tok, env.ProxyUser, env.ProxyGroups)
				if err != nil {
					return err
				}
				// A end-user admin (group bound to cluster-admin) creating a
				// workload through the proxy. Scoped to the test namespace.
				p := sleepPod("proxy-pod", env.Image, map[string]string{"audit-test": "proxy"})
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				if _, err := cl.CoreV1().Pods(env.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("proxied user create pod: %w", err)
				}
				if _, err := cl.RbacV1().RoleBindings(env.Namespace).Create(ctx, &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "proxy-rb"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "proxy-grantee-" + env.RunID, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
				}, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("proxied user create rolebinding: %w", err)
				}
				_ = cl.CoreV1().Pods(env.Namespace).Delete(ctx, "proxy-pod", metav1.DeleteOptions{})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				proxy := env.ProxySA
				return []audit.Expect{
					{
						// The important requirement: a privileged pod created by a
						// end user through the proxy must be recorded WITH the end user
						// identity AND with the body (so privileged/hostPath is visible).
						Desc: "privileged pod through the proxy logged with body and end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: "proxy-pod", User: proxy},
						Level: "RequestResponse", RequestBody: audit.Required, RequestBodyContains: []string{`"privileged":true`},
						Impersonated: env.ProxyUser, ImpersonatedGroups: env.ProxyGroups,
					},
					{
						Desc: "RoleBinding created through the proxy logged with body and end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "rolebindings", Namespace: env.Namespace, Name: "proxy-rb", User: proxy},
						Level: "Request", RequestBody: audit.Required, Impersonated: env.ProxyUser, Gap: gapNonCoreBody,
					},
					{
						// The minimum the requirement asks for: whatever the level,
						// at least one event for the pod create must name the end
						// user behind the proxy.
						Desc: "some event carries the impersonated end-user identity", Requirement: ReqProxy,
						Match:     audit.Match{Resource: "pods", Namespace: env.Namespace, Name: "proxy-pod", User: proxy, ImpersonatedUser: env.ProxyUser},
						MinEvents: 1,
					},
				}
			},
		},
		{
			Name:     "authproxy-impersonated-read",
			Optional: true,
			Needs:    needsProxy,
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.ProxySANamespace(), env.ProxySAName())
				if err != nil {
					return fmt.Errorf("mint token for %s/%s: %w", env.ProxySANamespace(), env.ProxySAName(), err)
				}
				cl, err := clientAs(env, tok, env.ProxyUser, env.ProxyGroups)
				if err != nil {
					return err
				}
				// End-user reads through the proxy: listing workloads and reading a
				// configmap. Read-only, scoped to the test namespace.
				if _, err := cl.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
					return fmt.Errorf("proxied user list pods: %w", err)
				}
				if _, err := cl.CoreV1().ConfigMaps(env.Namespace).List(ctx, metav1.ListOptions{}); err != nil {
					return fmt.Errorf("proxied user list configmaps: %w", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				proxy := env.ProxySA
				return []audit.Expect{
					{
						Desc: "end-user pod list through the proxy is logged with the end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, User: proxy, ImpersonatedUser: env.ProxyUser},
						Level: "RequestResponse",
					},
					{
						Desc: "end-user configmap list through the proxy is logged", Requirement: ReqProxy,
						Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: env.Namespace, User: proxy, ImpersonatedUser: env.ProxyUser},
						Level: "Metadata",
					},
				}
			},
		},
		{
			Name: "impersonation-groups-recorded",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A human admin (real user) impersonating a user with groups. This
				// request IS logged (real user is human), so it proves the audit
				// format records impersonatedUser AND its groups when not dropped.
				cl, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{
						UserName: "audit-impgroups-" + env.RunID,
						Groups:   []string{"audit-group-a", "audit-group-b"},
					}
				}))
				if err != nil {
					return err
				}
				_, err = cl.CoreV1().ConfigMaps(env.Namespace).List(ctx, metav1.ListOptions{})
				return ignoreForbidden(err)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "impersonatedUser groups are recorded in the event", Requirement: ReqImpersonate,
					Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: env.Namespace, ImpersonatedUser: "audit-impgroups-" + env.RunID},
					Level: "Metadata", Impersonated: "audit-impgroups-" + env.RunID,
					ImpersonatedGroups: []string{"audit-group-a", "audit-group-b"},
				}}
			},
		},
		{
			// Guards the ordering bug found during review: if the proxy write
			// rule is placed ABOVE the secrets rule, an end user creating a secret
			// through the proxy would be logged at Request and leak the secret data.
			// The secrets rule must win, keeping the proxy secret writes at Metadata.
			Name:     "authproxy-secret-write-no-leak",
			Optional: true,
			Needs:    needsProxy,
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.ProxySANamespace(), env.ProxySAName())
				if err != nil {
					return fmt.Errorf("mint token for %s/%s: %w", env.ProxySANamespace(), env.ProxySAName(), err)
				}
				cl, err := clientAs(env, tok, env.ProxyUser, env.ProxyGroups)
				if err != nil {
					return err
				}
				value := "PROXY-SECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("proxy secret value", value)
				env.AddMarker("proxy secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value)))
				if _, err := cl.CoreV1().Secrets(env.Namespace).Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "proxy-secret"},
					StringData: map[string]string{"password": value},
				}, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("proxied user create secret: %w", err)
				}
				return cl.CoreV1().Secrets(env.Namespace).Delete(ctx, "proxy-secret", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				proxy := env.ProxySA
				return []audit.Expect{{
					Desc: "secret written by an end user through the proxy stays at Metadata with no body (no leak)", Requirement: ReqProxy,
					Match: audit.Match{Verb: "create", Resource: "secrets", Namespace: env.Namespace, Name: "proxy-secret", User: proxy},
					Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, Impersonated: env.ProxyUser,
				}}
				// The global no-credential-leak check additionally scans every
				// event for the marker value, catching any level regression.
			},
		},

		// ==================================================================
		// Simulated security incidents
		//
		// All scenarios are scoped to the test namespace or create-then-delete
		// uniquely named cluster objects. Nothing running on the cluster is
		// modified, no real secret value is read (secrets stay at Metadata),
		// and the one host-mounting pod is made permanently unschedulable so it
		// never lands on a node.
		// ==================================================================
		{
			Name: "incident-privilege-escalation",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A cluster-admin (or a compromised admin credential) grants
				// cluster-admin to an attacker principal, then removes it. The
				// event is the crown-jewel audit record.
				name := env.Name("pwn")
				if _, err := env.Client.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"audit-test": env.RunID}},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "audit-attacker-" + env.RunID, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Client.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("pwn")
				return []audit.Expect{
					{
						Desc: "cluster-admin self-grant (ClusterRoleBinding to cluster-admin) logged with body", Requirement: ReqIncident,
						Match: audit.Match{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Name: name},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"cluster-admin", "audit-attacker-" + env.RunID}, Gap: gapNonCoreBody,
					},
					{
						Desc: "removal of the malicious binding is logged", Requirement: ReqIncident,
						Match: audit.Match{Verb: "delete", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Name: name},
						Level: "Metadata",
					},
				}
			},
		},
		{
			Name: "incident-rbac-escalation-denied",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A restricted unprivileged workload tries to escalate to cluster-admin.
				tok, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				_, err = cl.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: env.Name("escalate")},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saRestricted, Namespace: env.Namespace}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
				}, metav1.CreateOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA creating clusterrolebinding, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:" + env.Namespace + ":" + saRestricted
				return []audit.Expect{{
					Desc: "denied privilege escalation attempt (403 clusterrolebinding create) is logged", Requirement: ReqIncident,
					Match: audit.Match{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", User: user, ResponseCode: 403},
					Level: "Metadata", Code: 403, Annotations: map[string]string{"authorization.k8s.io/decision": "forbid"},
				}}
			},
		},
		{
			Name: "incident-secret-exfiltration",
			Act: func(ctx context.Context, env *audit.Env) error {
				// 1. Restricted unprivileged SA tries to sweep secrets cluster-wide and
				//    in kube-system (both denied).
				tok, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Secrets("").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for cluster-wide secret list, got %v", err)
				}
				if _, err := cl.CoreV1().Secrets("kube-system").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for kube-system secret list, got %v", err)
				}
				// 2. An admin credential sweeps all secrets cluster-wide (a real
				//    exfiltration path). Read-only; Metadata level guarantees no
				//    secret value is captured in the log.
				if _, err := env.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{Limit: 200}); err != nil {
					return fmt.Errorf("admin cluster-wide secret list: %w", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:" + env.Namespace + ":" + saRestricted
				forbid := map[string]string{"authorization.k8s.io/decision": "forbid"}
				return []audit.Expect{
					{
						Desc: "denied cluster-wide secret sweep by unprivileged SA is logged", Requirement: ReqIncident,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: "", User: user, ResponseCode: 403},
						Level: "Metadata", Code: 403, Annotations: forbid,
					},
					{
						Desc: "denied kube-system secret sweep by unprivileged SA is logged", Requirement: ReqIncident,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: "kube-system", User: user, ResponseCode: 403},
						Level: "Metadata", Code: 403, Annotations: forbid,
					},
					{
						Desc: "admin cluster-wide secret sweep is logged at Metadata (no values)", Requirement: ReqIncident,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: "", User: env.AdminUser, ResponseCode: 200},
						Level: "Metadata", ResponseBody: audit.Forbidden, RequestBody: audit.Forbidden,
					},
				}
			},
		},
		{
			Name: "incident-rogue-node",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A compromised kubelet credential (rogue worker). Impersonate a
				// node identity and try to read secrets it should not see and to
				// enumerate all pods. All read-only; no real secret value fetched
				// (targets a nonexistent name and secrets stay Metadata).
				//
				// NB: this impersonates from the admin credential, so the audit
				// policy matches the real (human) user and DOES log the reads,
				// which proves the node identity is captured in impersonatedUser.
				// A genuine rogue kubelet authenticates with its own certificate
				// (real user in group system:nodes); whether its reads are
				// logged depends on whether the policy drops that group, which
				// the global managed-group expectations check when the profile
				// lists system:nodes.
				nodes, err := env.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
				if err != nil || len(nodes.Items) == 0 {
					return fmt.Errorf("list nodes: %w", err)
				}
				nodeName := nodes.Items[len(nodes.Items)-1].Name
				env.RogueNode = nodeName
				cl, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{UserName: "system:node:" + nodeName, Groups: []string{"system:nodes"}}
				}))
				if err != nil {
					return err
				}
				// Secret in kube-system it has no business reading.
				_, _ = cl.CoreV1().Secrets("kube-system").Get(ctx, "audit-nonexistent-"+env.RunID, metav1.GetOptions{})
				// Cluster-wide pod enumeration (beyond its own node).
				_, _ = cl.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 50})
				// Cluster-wide secret enumeration.
				_, _ = cl.CoreV1().Secrets("").List(ctx, metav1.ListOptions{Limit: 50})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "rogue node reading a kube-system secret is logged (secrets rule precedes the node-read drop)", Requirement: ReqIncident,
						Match: audit.Match{Verb: "get", Resource: "secrets", Namespace: "kube-system", ImpersonatedUser: "system:node:" + env.RogueNode},
						Level: "Metadata",
					},
					{
						Desc: "rogue node cluster-wide secret sweep is logged", Requirement: ReqIncident,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: "", ImpersonatedUser: "system:node:" + env.RogueNode},
						Level: "Metadata",
					},
					{
						// Logged here because the impersonator is the human admin;
						// see the note in Act. The real-kubelet drop is asserted by
						// the global "reads by system:nodes are dropped" check.
						Desc: "node-identity pod enumeration is attributed to the node", Requirement: ReqIncident,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: "", ImpersonatedUser: "system:node:" + env.RogueNode},
						Level: "RequestResponse",
					},
				}
			},
		},
		{
			Name: "incident-rogue-workload-hostmount",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A container-breakout manifest: privileged, hostPID, host root and
				// the container runtime socket mounted. Made permanently
				// unschedulable (impossible nodeSelector) so it never runs.
				p := sleepPod("breakout", env.Image, map[string]string{"audit-test": "breakout"})
				p.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				p.Spec.HostPID = true
				p.Spec.HostNetwork = true
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
					Privileged: boolp(true),
					RunAsUser:  int64p(0),
				}
				hostPathDir := corev1.HostPathDirectory
				sock := corev1.HostPathSocket
				p.Spec.Volumes = []corev1.Volume{
					{Name: "hostroot", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/", Type: &hostPathDir}}},
					{Name: "crisock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd/containerd.sock", Type: &sock}}},
				}
				p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
					{Name: "hostroot", MountPath: "/host"},
					{Name: "crisock", MountPath: "/run/cri.sock"},
				}
				if _, err := env.Client.CoreV1().Pods(env.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return ignoreForbidden(err)
				}
				return env.Client.CoreV1().Pods(env.Namespace).Delete(ctx, "breakout", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "container-breakout pod (host root + CRI socket + privileged) logged with full body", Requirement: ReqIncident,
					Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: env.Namespace, Name: "breakout"},
					Level: "RequestResponse", RequestBody: audit.Required,
					RequestBodyContains: []string{`"privileged":true`, `"hostPID":true`, "containerd.sock", `"path":"/"`},
				}}
			},
		},
		{
			Name: "incident-exec-attempt-kube-system",
			Act: func(ctx context.Context, env *audit.Env) error {
				// Lateral movement: a restricted unprivileged SA tries to exec into a
				// control-plane component. Denied at authz; the attempt must be
				// logged. Targets a nonexistent pod name so no real pod is touched.
				tok, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				req := cl.CoreV1().RESTClient().Post().
					Resource("pods").Namespace("kube-system").Name("audit-target-"+env.RunID).SubResource("exec").
					VersionedParams(&corev1.PodExecOptions{Command: []string{"sh"}, Stdin: true, Stdout: true}, scheme.ParameterCodec)
				ex, err := remotecommand.NewSPDYExecutor(env.ConfigFor(func(c *rest.Config) {
					c.TLSClientConfig.CertData, c.TLSClientConfig.KeyData = nil, nil
					c.TLSClientConfig.CertFile, c.TLSClientConfig.KeyFile = "", ""
					c.BearerToken = tok
					c.BearerTokenFile = ""
				}), "POST", req.URL())
				if err != nil {
					return err
				}
				// Expected to fail (403); we only care that the attempt is audited.
				_ = ex.StreamWithContext(ctx, remotecommand.StreamOptions{})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				user := "system:serviceaccount:" + env.Namespace + ":" + saRestricted
				return []audit.Expect{{
					Desc: "denied exec into a kube-system pod (lateral movement) is logged", Requirement: ReqIncident,
					Match: audit.Match{Resource: "pods", Subresource: "exec", Namespace: "kube-system", User: user},
					Level: "Request", Annotations: map[string]string{"authorization.k8s.io/decision": "forbid"},
				}}
			},
		},
		{
			Name: "incident-tamper-admission-webhook",
			Act: func(ctx context.Context, env *audit.Env) error {
				// Disabling admission control is a classic post-exploitation step.
				// Create then delete our own uniquely named, inert webhook config
				// (URL unreachable, failurePolicy Ignore) so no real admission is
				// affected. Also verify a restricted SA cannot do it.
				name := env.Name("tamper")
				fail := admissionv1.Ignore
				none := admissionv1.SideEffectClassNone
				wh := &admissionv1.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"audit-test": env.RunID}},
					Webhooks: []admissionv1.ValidatingWebhook{{
						Name:                    env.Domain,
						ClientConfig:            admissionv1.WebhookClientConfig{URL: strPtr("https://127.0.0.1:1/nope")},
						FailurePolicy:           &fail,
						SideEffects:             &none,
						AdmissionReviewVersions: []string{"v1"},
						Rules: []admissionv1.RuleWithOperations{{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule:       admissionv1.Rule{APIGroups: []string{env.Domain}, APIVersions: []string{"v1"}, Resources: []string{"nothings"}},
						}},
					}},
				}
				if _, err := env.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, wh, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, env.Namespace, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					// Some restricted SAs may be allowed to list; only the delete
					// below is asserted, so don't fail here.
					_ = err
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("tamper")
				g := "admissionregistration.k8s.io"
				return []audit.Expect{
					{
						Desc: "admission webhook config create (tampering with security controls) logged with body", Requirement: ReqIncident,
						Match: audit.Match{Verb: "create", Group: g, Resource: "validatingwebhookconfigurations", Name: name},
						Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody,
					},
					{
						Desc: "admission webhook config delete logged with who did it", Requirement: ReqIncident,
						Match: audit.Match{Verb: "delete", Group: g, Resource: "validatingwebhookconfigurations", Name: name},
						Level: "Metadata",
					},
				}
			},
		},

		// ------------------------------------------------------------------
		// Teardown (also a scenario: namespace deletion must be logged)
		// ------------------------------------------------------------------
		{
			Name: "namespace-delete",
			Act: func(ctx context.Context, env *audit.Env) error {
				return env.Client.CoreV1().Namespaces().Delete(ctx, env.Namespace, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "namespace delete is logged", Requirement: ReqResources,
					Match: audit.Match{Verb: "delete", Resource: "namespaces", Name: env.Namespace},
					Level: "Request",
				}}
			},
		},
	}
}

func strPtr(s string) *string { return &s }

// GlobalExpectations are checked over every event written during the run,
// regardless of who caused it.
func GlobalExpectations(env *audit.Env) []audit.Expect {
	out := edgeGlobalExpectations(env)
	out = append(out, []audit.Expect{
		{Desc: "no RequestReceived stage anywhere", Requirement: ReqHygiene, Match: audit.Match{Stage: "RequestReceived", AnyUA: true}, Level: "None"},
		{Desc: "health endpoints never logged", Requirement: ReqNoise, Match: audit.Match{NonResource: true, URIPrefix: "/healthz", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "readyz never logged", Requirement: ReqNoise, Match: audit.Match{NonResource: true, URIPrefix: "/readyz", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "livez never logged", Requirement: ReqNoise, Match: audit.Match{NonResource: true, URIPrefix: "/livez", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "events never logged", Requirement: ReqNoise, Match: audit.Match{Resource: "events", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "authenticated API discovery (/api*) is dropped", Requirement: ReqNoise, Match: audit.Match{NonResource: true, URIPrefix: "/api", UserGroup: "system:authenticated", AnyUA: true}, Level: "None"},
		{Desc: "secrets never carry bodies", Requirement: ReqHygiene, Match: audit.Match{Resource: "secrets", AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden},
		{Desc: "serviceaccounts/token never carry a response body (the issued token)", Requirement: ReqHygiene, Match: audit.Match{Resource: "serviceaccounts", Subresource: "token", AnyUA: true}, ResponseBody: audit.Forbidden, Tier: audit.Invariant},
		{Desc: "tokenreviews never carry bodies", Requirement: ReqHygiene, Match: audit.Match{Resource: "tokenreviews", AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, AllowNone: true},
		{Desc: "kube-apiserver own writes (CRD status, apiservices, ipaddresses, quota status) are Metadata at most", Requirement: ReqNoise, Match: audit.Match{User: "system:apiserver", Verbs: []string{"create", "update", "patch", "delete"}, AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true, Gap: gapNoise},
		{Desc: "kube-apiserver own reads are dropped", Requirement: ReqNoise, Match: audit.Match{User: "system:apiserver", Verbs: []string{"get", "list", "watch"}, AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "lease heartbeats by controllers are dropped", Requirement: ReqNoise, Match: audit.Match{Resource: "leases", Verbs: []string{"get", "update", "patch"}, UserPrefix: "system:kube-", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "lease heartbeats by service accounts are dropped", Requirement: ReqNoise, Match: audit.Match{Resource: "leases", Verbs: []string{"get", "update", "patch"}, UserGroup: "system:serviceaccounts", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "lease heartbeats by kubelets are dropped", Requirement: ReqNoise, Match: audit.Match{Resource: "leases", Verbs: []string{"get", "update", "patch"}, UserGroup: "system:nodes", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "controller-manager/scheduler reads are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"get", "list", "watch"}, UserPrefix: "system:kube-", NotResources: []string{"secrets"}, AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "controller-manager/scheduler status writes are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"update", "patch"}, Subresource: "status", UserPrefix: "system:kube-", AnyUA: true}, Level: "None", Gap: gapNoise},
		{Desc: "the controller-leader configmap is never logged", Requirement: ReqNoise, Match: audit.Match{Resource: "configmaps", Name: "controller-leader", AnyUA: true}, Level: "None"},
		{Desc: "kube-system configmaps are logged at Request by everyone", Requirement: ReqResources, Match: audit.Match{Resource: "configmaps", Namespace: "kube-system", NotUser: "system:apiserver", AnyUA: true}, Level: "Request", AllowNone: true},
	}...)
	// The baseline treats no group as the platform, so by default this adds
	// nothing. A profile that lists managedGroups (for policy/hardened.yaml or
	// a policy like it) gets these checks. The authenticating proxy SA is
	// intentionally logged, so it is excluded from the "reads are dropped"
	// check; other SAs of the proxy namespace are still expected to be dropped.
	proxySA := env.ProxySA
	for _, g := range env.ManagedGroups() {
		out = append(out,
			audit.Expect{Desc: "reads by " + g + " are dropped (except secrets and the proxy account)", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"get", "list", "watch"}, UserGroup: g, NotUser: proxySA, NotResources: []string{"secrets"}, AnyUA: true}, Level: "None"},
			audit.Expect{Desc: "status writes by " + g + " in the policy's API groups are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"update", "patch"}, Subresource: "status", UserGroup: g, Groups: env.StatusGroups(), AnyUA: true}, Level: "None"},
			audit.Expect{
				Desc: "status writes by " + g + " in other API groups", Requirement: ReqNoise,
				Match: audit.Match{Verbs: []string{"update", "patch"}, Subresource: "status", UserGroup: g, NotGroups: env.StatusGroups(), AnyUA: true}, Level: "None",
				Gap: "status subresource writes in API groups not listed in the policy (e.g. operator.tigera.io, apiextensions.k8s.io by system:apiserver) fall through to Metadata; extend the */status group list if they turn out noisy",
			},
			audit.Expect{Desc: "tokenreviews/subjectaccessreviews by " + g + " are dropped", Requirement: ReqNoise, Match: audit.Match{Verb: "create", UserGroup: g, Resources: []string{"tokenreviews", "subjectaccessreviews"}, AnyUA: true}, Level: "None"},
		)
	}
	return out
}

// RequirementOrder is the order the coverage table prints requirements in.
var RequirementOrder = []string{
	ReqResources, ReqRBAC, ReqExec, ReqPrivileged, ReqAuthFail, ReqAnonymous, ReqImpersonate,
	ReqTokens, ReqSecrets, ReqHumans, ReqNoise, ReqHygiene, ReqProxy, ReqIncident,
	ReqEdge, ReqEcosystem, ReqBudget,
}
