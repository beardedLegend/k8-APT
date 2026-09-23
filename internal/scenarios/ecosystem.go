package scenarios

// Ecosystem scenarios: what a cluster sees from the tools and add-ons that
// run on almost every real cluster rather than from kubectl alone — Helm
// releases and hooks, ConfigMap and Secret shapes that charts produce,
// admission policy (Pod Security, ValidatingAdmissionPolicy), API priority
// and fairness, and the custom resources of the common operators
// (cert-manager, Prometheus Operator, Argo CD, Flux, Kyverno, Gatekeeper,
// External Secrets, Sealed Secrets, Velero, Istio, Cilium, Gateway API,
// Traefik, CSI snapshots).
//
// The operator scenarios detect their API group through discovery and are
// skipped when it is not served, so nothing needs to be configured. They send
// their custom resources as dry-run creates: the API server audits a dry-run
// request exactly like a real one, and nothing is persisted, so no operator
// reconciles a test object, starts a backup or reconfigures admission.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	flowcontrolv1 "k8s.io/api/flowcontrol/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

const ReqEcosystem = "R17 ecosystem: Helm, operators, admission policy and add-ons"

const (
	helmRelease  = "audit-rel"
	psaEnforce   = "pod-security.kubernetes.io/enforce"
	psaAudit     = "pod-security.kubernetes.io/audit"
	psaViolation = "pod-security.kubernetes.io/audit-violations"
	vapFailure   = "validation.policy.admission.k8s.io/validation_failure"
)

// errNotInstalled marks an Act that found the add-on it exercises missing;
// the scenarios using it are Optional, so the run reports a skip.
var errNotInstalled = errors.New("not installed on this cluster")

// servedVersion returns the preferred version of an API group, or
// errNotInstalled when the cluster does not serve it.
func servedVersion(env *audit.Env, group string) (string, error) {
	groups, err := env.Client.Discovery().ServerGroups()
	if err != nil {
		return "", err
	}
	for _, g := range groups.Groups {
		if g.Name == group {
			return g.PreferredVersion.Version, nil
		}
	}
	return "", fmt.Errorf("API group %s: %w", group, errNotInstalled)
}

// firstNamespace returns the first of the candidates that exists.
func firstNamespace(ctx context.Context, env *audit.Env, candidates []string) (string, error) {
	for _, ns := range candidates {
		if _, err := env.Client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
			return ns, nil
		}
	}
	return "", fmt.Errorf("none of the namespaces %v exists: %w", candidates, errNotInstalled)
}

// helmPayload encodes a release the way Helm stores it: JSON, gzipped,
// base64. The values carry a password, as real chart values often do.
func helmPayload(env *audit.Env, revision int) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	fmt.Fprintf(zw, `{"name":%q,"version":%d,"config":{"auth":{"password":"HELM-VALUE-%s-do-not-log"}}}`, helmRelease, revision, env.RunID)
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func helmReleaseName(revision int) string {
	return fmt.Sprintf("sh.helm.release.v1.%s.v%d", helmRelease, revision)
}

// helmMeta is the metadata Helm puts on every object of a release.
func helmMeta(env *audit.Env, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "Helm",
			"app.kubernetes.io/instance":   helmRelease,
			"helm.sh/chart":                "audit-chart-0.1.0",
		},
		Annotations: map[string]string{
			"meta.helm.sh/release-name":      helmRelease,
			"meta.helm.sh/release-namespace": env.Namespace,
		},
	}
}

// opObject is one custom resource of an operator scenario.
type opObject struct {
	resource, kind string
	cluster        bool
	spec           map[string]any
}

// operatorScenario builds the scenario for one add-on: discover the group,
// dry-run create each object, expect each create in the log.
func operatorScenario(name, group string, namespaces []string, objects []opObject) Scenario {
	objName := func(env *audit.Env, o opObject) string {
		if o.cluster {
			return env.Name(strings.ToLower(o.kind))
		}
		return "audit-" + strings.ToLower(o.kind)
	}
	return Scenario{
		Name:     name,
		Optional: true,
		Act: func(ctx context.Context, env *audit.Env) error {
			version, err := servedVersion(env, group)
			if err != nil {
				return err
			}
			ns := env.Namespace
			if len(namespaces) > 0 {
				if ns, err = firstNamespace(ctx, env, namespaces); err != nil {
					return err
				}
			}
			for _, o := range objects {
				gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: o.resource}
				meta := map[string]any{
					"name":   objName(env, o),
					"labels": map[string]any{env.Label("marker"): "audit-op-" + env.RunID},
				}
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": group + "/" + version, "kind": o.kind, "metadata": meta, "spec": o.spec,
				}}
				ri := env.Dynamic.Resource(gvr)
				dry := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
				if o.cluster {
					_, err = ri.Create(ctx, obj, dry)
				} else {
					meta["namespace"] = ns
					_, err = ri.Namespace(ns).Create(ctx, obj, dry)
				}
				// Admission may reject a spec written for a different
				// version of the operator; the request is audited either way.
				if err != nil && (apierrors.IsNotFound(err) || isNoMatch(err)) {
					return fmt.Errorf("%s: %w", o.resource, errNotInstalled)
				}
			}
			return nil
		},
		Expect: func(env *audit.Env) []audit.Expect {
			var out []audit.Expect
			for _, o := range objects {
				m := audit.Match{Verb: "create", Group: group, Resource: o.resource, Name: objName(env, o), URIContains: "dryRun=All"}
				out = append(out,
					audit.Expect{Desc: o.kind + " (" + group + ") create is logged (any level)", Requirement: ReqEcosystem, Match: m, MinEvents: 1},
					audit.Expect{
						Desc: o.kind + " (" + group + ") create is logged with body", Requirement: ReqEcosystem, Match: m,
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-op-" + env.RunID}, Gap: gapNonCoreBody,
					},
				)
			}
			return out
		},
	}
}

// isNoMatch reports a "no matches for kind" error, which the dynamic client
// does not produce but a mapper-based client would.
func isNoMatch(err error) bool { return strings.Contains(err.Error(), "no matches for kind") }

// dynamicNS is a namespaced dynamic resource client.
type dynamicNS = dynamic.ResourceInterface

func kubernetesAnon(env *audit.Env) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(env.AnonymousConfig())
}

// EcosystemScenarios run after the edge cases and before the test namespace
// is deleted. They rely on the test namespace, the plain pod and audit-svc.
func EcosystemScenarios() []Scenario {
	return append(ecosystemCore(), operatorScenarios()...)
}

func ecosystemCore() []Scenario {
	return []Scenario{
		// ==================================================================
		// Helm
		//
		// Helm talks to the API server like any client; these scenarios
		// replay the requests `helm install`, `upgrade`, `history`,
		// `rollback` and `uninstall` make, without needing Helm itself.
		// ==================================================================
		{
			Name: "helm-release-lifecycle",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				secrets := env.Client.CoreV1().Secrets(ns)
				release := func(rev int, status string) (*corev1.Secret, error) {
					payload, err := helmPayload(env, rev)
					if err != nil {
						return nil, err
					}
					env.AddMarker(fmt.Sprintf("helm release payload v%d", rev), payload)
					env.AddMarker(fmt.Sprintf("helm release payload v%d (base64)", rev), base64.StdEncoding.EncodeToString([]byte(payload)))
					return secrets.Create(ctx, &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: helmReleaseName(rev), Labels: map[string]string{
							"owner": "helm", "name": helmRelease, "status": status, "version": fmt.Sprint(rev),
						}},
						Type: "helm.sh/release.v1",
						Data: map[string][]byte{"release": []byte(payload)},
					}, metav1.CreateOptions{})
				}
				history := func() error {
					_, err := secrets.List(ctx, metav1.ListOptions{LabelSelector: "owner=helm,name=" + helmRelease})
					return err
				}
				supersede := func(rev int) error {
					s, err := secrets.Get(ctx, helmReleaseName(rev), metav1.GetOptions{})
					if err != nil {
						return err
					}
					s.Labels["status"] = "superseded"
					_, err = secrets.Update(ctx, s, metav1.UpdateOptions{})
					return err
				}

				// install
				if err := history(); err != nil {
					return err
				}
				if _, err := release(1, "pending-install"); err != nil {
					return err
				}
				cm := &corev1.ConfigMap{ObjectMeta: helmMeta(env, "audit-rel-config"), Data: map[string]string{"log-level": "info"}}
				if _, err := env.Client.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
					return err
				}
				svc := &corev1.Service{ObjectMeta: helmMeta(env, "audit-rel"), Spec: corev1.ServiceSpec{
					Selector: map[string]string{"app.kubernetes.io/instance": helmRelease},
					Ports:    []corev1.ServicePort{{Port: 80}},
				}}
				if _, err := env.Client.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
					return err
				}
				labels := map[string]string{"app.kubernetes.io/instance": helmRelease}
				tmpl := sleepPod("", env.Image, labels)
				dep := &appsv1.Deployment{ObjectMeta: helmMeta(env, "audit-rel"), Spec: appsv1.DeploymentSpec{
					Replicas: int32p(0),
					Selector: &metav1.LabelSelector{MatchLabels: labels},
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: tmpl.Spec},
				}}
				if _, err := env.Client.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := secrets.Patch(ctx, helmReleaseName(1), types.MergePatchType, []byte(`{"metadata":{"labels":{"status":"deployed"}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}

				// upgrade: a three-way merge patch per changed object
				if _, err := release(2, "pending-upgrade"); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().ConfigMaps(ns).Patch(ctx, "audit-rel-config", types.StrategicMergePatchType, []byte(`{"data":{"log-level":"debug"}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.AppsV1().Deployments(ns).Patch(ctx, "audit-rel", types.StrategicMergePatchType,
					[]byte(`{"spec":{"template":{"metadata":{"annotations":{"checksum/config":"audit-upgrade-`+env.RunID+`"}}}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				if err := supersede(1); err != nil {
					return err
				}

				// history, rollback, uninstall
				if err := history(); err != nil {
					return err
				}
				if _, err := release(3, "deployed"); err != nil {
					return err
				}
				if err := supersede(2); err != nil {
					return err
				}
				if err := env.Client.AppsV1().Deployments(ns).Delete(ctx, "audit-rel", metav1.DeleteOptions{}); err != nil {
					return err
				}
				if err := env.Client.CoreV1().Services(ns).Delete(ctx, "audit-rel", metav1.DeleteOptions{}); err != nil {
					return err
				}
				if err := env.Client.CoreV1().ConfigMaps(ns).Delete(ctx, "audit-rel-config", metav1.DeleteOptions{}); err != nil {
					return err
				}
				for rev := 1; rev <= 3; rev++ {
					if err := secrets.Delete(ctx, helmReleaseName(rev), metav1.DeleteOptions{}); err != nil {
						return err
					}
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				rel := audit.Match{Resource: "secrets", Namespace: ns, NamePrefix: "sh.helm.release.v1." + helmRelease}
				with := func(m audit.Match, verb string) audit.Match { m.Verb = verb; return m }
				return []audit.Expect{
					{Desc: "each Helm release revision (secret driver) is logged at Metadata without its payload", Requirement: ReqEcosystem, Match: with(rel, "create"), Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, MinEvents: 3},
					{Desc: "Helm marking a revision superseded is logged at Metadata", Requirement: ReqEcosystem, Match: with(rel, "update"), Level: "Metadata", RequestBody: audit.Forbidden, MinEvents: 2},
					{Desc: "Helm marking a revision deployed is logged at Metadata", Requirement: ReqEcosystem, Match: with(rel, "patch"), Level: "Metadata", RequestBody: audit.Forbidden},
					{Desc: "helm uninstall deleting the release history is logged", Requirement: ReqEcosystem, Match: with(rel, "delete"), Level: "Metadata", MinEvents: 3},
					{
						Desc: "helm list/history (secret list by owner=helm) is logged with the selector in the URI", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "list", Resource: "secrets", Namespace: ns, URIContains: "owner%3Dhelm"},
						Level: "Metadata", ResponseBody: audit.Forbidden, MinEvents: 2,
					},
					{
						Desc: "Helm-managed service is logged with its release annotations", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "services", Namespace: ns, Name: "audit-rel"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"meta.helm.sh/release-name", `"app.kubernetes.io/managed-by":"Helm"`},
					},
					{
						Desc: "Helm-managed deployment is logged with its release annotations", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Group: "apps", Resource: "deployments", Namespace: ns, Name: "audit-rel"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"meta.helm.sh/release-name"}, Gap: gapNonCoreBody,
					},
					{
						Desc: "helm upgrade patch of a deployment is logged with the patch", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "patch", Group: "apps", Resource: "deployments", Namespace: ns, Name: "audit-rel"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-upgrade-" + env.RunID}, Gap: gapNonCoreBody,
					},
					{
						Desc: "helm upgrade patch of a configmap is logged at Metadata", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "patch", Resource: "configmaps", Namespace: ns, Name: "audit-rel-config"},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
				}
			},
		},
		{
			// HELM_DRIVER=configmap keeps the release — chart values included —
			// in a ConfigMap. Outside kube-system the baseline logs it at
			// Metadata; in kube-system, where charts for cluster add-ons are
			// often installed, it logs the whole payload.
			Name: "helm-release-configmap-driver",
			Act: func(ctx context.Context, env *audit.Env) error {
				// A revision number of its own, so the payload differs from the
				// secret-driver releases whose payload is a leak marker.
				payload, err := helmPayload(env, 101)
				if err != nil {
					return err
				}
				mk := func(ns, name string) error {
					c := env.Client.CoreV1().ConfigMaps(ns)
					if _, err := c.Create(ctx, &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"owner": "helm", "name": helmRelease, "status": "deployed", "version": "1"}},
						Data:       map[string]string{"release": payload},
					}, metav1.CreateOptions{}); err != nil {
						return err
					}
					if _, err := c.List(ctx, metav1.ListOptions{LabelSelector: "owner=helm"}); err != nil {
						return err
					}
					return c.Delete(ctx, name, metav1.DeleteOptions{})
				}
				if err := mk(env.Namespace, helmReleaseName(1)); err != nil {
					return err
				}
				return mk("kube-system", env.Name("helm")+".v1")
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "Helm release stored as a configmap is logged at Metadata without its payload", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: env.Namespace, Name: helmReleaseName(1)},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
					{
						Desc: "Helm release stored as a kube-system configmap is logged without its payload", Requirement: ReqEcosystem,
						Match:       audit.Match{Verb: "create", Resource: "configmaps", Namespace: "kube-system", Name: env.Name("helm") + ".v1"},
						RequestBody: audit.Forbidden,
						Gap:         "the baseline logs kube-system configmaps at Request, so a Helm release stored there with HELM_DRIVER=configmap puts the chart values, passwords included, into the log; exclude configmaps labelled owner=helm or use the secret driver",
					},
					{
						Desc: "Helm release stored as a kube-system configmap is logged (any level)", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: "kube-system", Name: env.Name("helm") + ".v1"}, MinEvents: 1,
					},
				}
			},
		},
		{
			// Hooks and tests are the Helm objects nobody looks at: a
			// pre-install Job and a test Pod, each created and deleted by Helm
			// around the release. Both are made unschedulable.
			Name: "helm-hooks-and-tests",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				never := map[string]string{env.Label("never-schedule"): env.RunID}
				hook := helmMeta(env, "audit-rel-migrate")
				hook.Annotations["helm.sh/hook"] = "pre-install,pre-upgrade"
				hook.Annotations["helm.sh/hook-delete-policy"] = "before-hook-creation,hook-succeeded"
				pod := sleepPod("", env.Image, nil)
				pod.Spec.RestartPolicy = corev1.RestartPolicyNever
				pod.Spec.NodeSelector = never
				if _, err := env.Client.BatchV1().Jobs(ns).Create(ctx, &batchv1.Job{
					ObjectMeta: hook,
					Spec:       batchv1.JobSpec{BackoffLimit: int32p(0), Template: corev1.PodTemplateSpec{Spec: pod.Spec}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				test := sleepPod("audit-rel-test", env.Image, nil)
				test.ObjectMeta = helmMeta(env, "audit-rel-test")
				test.Annotations["helm.sh/hook"] = "test"
				test.Spec.NodeSelector = never
				if _, err := env.Client.CoreV1().Pods(ns).Create(ctx, test, metav1.CreateOptions{}); err != nil {
					return err
				}
				bg := metav1.DeletePropagationBackground
				if err := env.Client.BatchV1().Jobs(ns).Delete(ctx, "audit-rel-migrate", metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil {
					return err
				}
				return env.Client.CoreV1().Pods(ns).Delete(ctx, "audit-rel-test", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "Helm hook job is logged with its hook annotations", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Group: "batch", Resource: "jobs", Namespace: ns, Name: "audit-rel-migrate"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"helm.sh/hook"}, Gap: gapNonCoreBody,
					},
					{Desc: "Helm hook job delete is logged", Requirement: ReqEcosystem, Match: audit.Match{Verb: "delete", Group: "batch", Resource: "jobs", Namespace: ns, Name: "audit-rel-migrate"}, Level: "Metadata"},
					{
						Desc: "Helm test pod is logged with its hook annotation", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: "audit-rel-test"},
						Level: "RequestResponse", RequestBody: audit.Required, RequestBodyContains: []string{`"helm.sh/hook":"test"`},
					},
				}
			},
		},
		{
			// Charts routinely ship ClusterRoles that aggregate into other
			// roles. The aggregation controller then rewrites the parent role:
			// a privilege change nobody requested directly. The parent here is
			// the run's own role, so no real role changes.
			Name: "clusterrole-aggregation",
			Act: func(ctx context.Context, env *audit.Env) error {
				crs := env.Client.RbacV1().ClusterRoles()
				selector := env.Label("aggregate-to-" + env.RunID)
				if _, err := crs.Create(ctx, &rbacv1.ClusterRole{
					ObjectMeta:      metav1.ObjectMeta{Name: env.Name("agg-parent")},
					AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{selector: "true"}}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := crs.Create(ctx, &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: env.Name("agg-child"), Labels: map[string]string{selector: "true"}},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{env.Domain}, Resources: []string{"nothings"}, Verbs: []string{"get"}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				deadline := time.Now().Add(20 * time.Second)
				for {
					p, err := crs.Get(ctx, env.Name("agg-parent"), metav1.GetOptions{})
					if err != nil {
						return err
					}
					if len(p.Rules) > 0 {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("the aggregation controller did not fill %s", env.Name("agg-parent"))
					}
					time.Sleep(time.Second)
				}
				if err := crs.Delete(ctx, env.Name("agg-child"), metav1.DeleteOptions{}); err != nil {
					return err
				}
				return crs.Delete(ctx, env.Name("agg-parent"), metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				g := "rbac.authorization.k8s.io"
				return []audit.Expect{
					{
						Desc: "aggregating ClusterRole is logged with its aggregation label", Requirement: ReqRBAC,
						Match: audit.Match{Verb: "create", Group: g, Resource: "clusterroles", Name: env.Name("agg-child")},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"aggregate-to-" + env.RunID}, Gap: gapNonCoreBody,
					},
					{
						Desc: "the aggregation controller rewriting the parent role is logged", Requirement: ReqRBAC,
						Match:     audit.Match{Verbs: []string{"update", "patch"}, Group: g, Resource: "clusterroles", Name: env.Name("agg-parent"), UserPrefix: "system:", AnyUA: true},
						MinEvents: 1,
					},
				}
			},
		},

		// ==================================================================
		// ConfigMaps and Secrets in the shapes charts produce
		// ==================================================================
		{
			Name: "configmap-patterns",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				c := env.Client.CoreV1().ConfigMaps(ns)
				// immutable, then an update it refuses (422)
				if _, err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "audit-immutable"}, Immutable: boolp(true), Data: map[string]string{"k": "v"}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := c.Patch(ctx, "audit-immutable", types.MergePatchType, []byte(`{"data":{"k":"changed"}}`), metav1.PatchOptions{}); !apierrors.IsInvalid(err) {
					return fmt.Errorf("expected 422 changing an immutable configmap, got %v", err)
				}
				// binaryData and a large configmap (dashboards, rule files)
				big := strings.Repeat("audit-large-configmap-", 20000)
				if _, err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "audit-large"}, Data: map[string]string{"dashboard.json": big}, BinaryData: map[string][]byte{"logo.png": {0x89, 'P', 'N', 'G'}}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// the leader election configmap the baseline drops by name
				if _, err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "controller-leader"}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := c.Get(ctx, "controller-leader", metav1.GetOptions{}); err != nil {
					return err
				}
				// every namespace gets kube-root-ca.crt
				if _, err := c.Get(ctx, "kube-root-ca.crt", metav1.GetOptions{}); err != nil {
					return err
				}
				// a pod consuming configmaps through envFrom and a projected volume
				p := sleepPod("cm-consumer", env.Image, nil)
				p.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "audit-immutable"}}}}
				p.Spec.Volumes = []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
					{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "audit-large"}}},
					{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}}},
				}}}}}
				p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "cfg", MountPath: "/cfg"}}
				if _, err := env.Client.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := env.Client.CoreV1().Pods(ns).Delete(ctx, "cm-consumer", metav1.DeleteOptions{}); err != nil {
					return err
				}
				return c.Delete(ctx, "controller-leader", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				cm := func(verb, name string) audit.Match {
					return audit.Match{Verb: verb, Resource: "configmaps", Namespace: ns, Name: name}
				}
				return []audit.Expect{
					{Desc: "immutable configmap create is logged at Metadata", Requirement: ReqEcosystem, Match: cm("create", "audit-immutable"), Level: "Metadata", RequestBody: audit.Forbidden},
					{Desc: "refused change to an immutable configmap (422) is logged", Requirement: ReqEdge, Match: cm("patch", "audit-immutable"), Level: "Metadata", Code: 422},
					{Desc: "large configmap with binaryData is logged without its body", Requirement: ReqEcosystem, Match: cm("create", "audit-large"), Level: "Metadata", RequestBody: audit.Forbidden},
					{Desc: "the controller-leader configmap is not logged", Requirement: ReqNoise, Match: audit.Match{Resource: "configmaps", Namespace: ns, Name: "controller-leader"}, Level: "None"},
					{Desc: "kube-root-ca.crt read by a human is logged", Requirement: ReqHumans, Match: cm("get", "kube-root-ca.crt"), Level: "Metadata"},
					{
						Desc: "pod consuming configmaps (envFrom, projected volume) is logged with the references", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: "cm-consumer"},
						Level: "RequestResponse", RequestBody: audit.Required, RequestBodyContains: []string{"configMapRef", "projected", "kube-root-ca.crt"},
					},
				}
			},
		},
		{
			// Read-only: the configmaps an admin inspects when debugging a
			// cluster. Missing ones (other distributions) are simply 404s.
			Name: "configmap-well-known-reads",
			Act: func(ctx context.Context, env *audit.Env) error {
				ks := env.Client.CoreV1().ConfigMaps("kube-system")
				for _, name := range []string{"coredns", "kube-proxy", "kubeadm-config", "kubelet-config", "extension-apiserver-authentication", "cluster-autoscaler-status"} {
					if _, err := ks.Get(ctx, name, metav1.GetOptions{}); ignoreNotFound(err) != nil {
						return err
					}
				}
				if _, err := ks.List(ctx, metav1.ListOptions{}); err != nil {
					return err
				}
				// kubeadm's bootstrap discovery document, readable anonymously
				anon, err := kubernetesAnon(env)
				if err != nil {
					return err
				}
				_, _ = anon.CoreV1().ConfigMaps("kube-public").Get(ctx, "cluster-info", metav1.GetOptions{})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "kube-system configmap reads by a human are logged at Request (the kube-system rule covers every verb)", Requirement: ReqHumans,
						Match: audit.Match{Verb: "get", Resource: "configmaps", Namespace: "kube-system", User: env.AdminUser},
						Level: "Request", MinEvents: 6,
					},
					{
						Desc: "kube-system configmap list by a human is logged", Requirement: ReqHumans,
						Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: "kube-system", User: env.AdminUser},
						Level: "Request",
					},
					{
						Desc: "anonymous read of kube-public/cluster-info is logged", Requirement: ReqAnonymous,
						Match: audit.Match{Verb: "get", Resource: "configmaps", Namespace: "kube-public", Name: "cluster-info", User: "system:anonymous"},
						Level: "Metadata",
					},
				}
			},
		},
		{
			// The secret types charts and operators create, and an image pull
			// secret attached to a service account.
			Name: "secret-types",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				secrets := env.Client.CoreV1().Secrets(ns)
				v := func(what string) string {
					val := "SECRET-TYPE-" + strings.ToUpper(what) + "-" + env.RunID + "-do-not-log"
					env.AddMarker(what+" value", val)
					env.AddMarker(what+" value (base64)", base64.StdEncoding.EncodeToString([]byte(val)))
					return val
				}
				dockerAuth := base64.StdEncoding.EncodeToString([]byte("audit:" + v("registry password")))
				env.AddMarker("registry auth", dockerAuth)
				for _, s := range []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "audit-tls"}, Type: corev1.SecretTypeTLS, StringData: map[string]string{"tls.crt": "-----BEGIN CERTIFICATE-----\n" + v("tls cert") + "\n-----END CERTIFICATE-----", "tls.key": "-----BEGIN PRIVATE KEY-----\n" + v("tls key") + "\n-----END PRIVATE KEY-----"}},
					{ObjectMeta: metav1.ObjectMeta{Name: "audit-pull"}, Type: corev1.SecretTypeDockerConfigJson, StringData: map[string]string{".dockerconfigjson": `{"auths":{"registry.example.invalid":{"auth":"` + dockerAuth + `"}}}`}},
					{ObjectMeta: metav1.ObjectMeta{Name: "audit-basic"}, Type: corev1.SecretTypeBasicAuth, StringData: map[string]string{"username": "audit", "password": v("basic auth")}},
					{ObjectMeta: metav1.ObjectMeta{Name: "audit-ssh"}, Type: corev1.SecretTypeSSHAuth, StringData: map[string]string{"ssh-privatekey": v("ssh key")}},
					{ObjectMeta: metav1.ObjectMeta{Name: "audit-opaque"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"blob": []byte(v("binary"))}},
				} {
					if _, err := secrets.Create(ctx, s, metav1.CreateOptions{}); err != nil {
						return fmt.Errorf("create %s secret: %w", s.Type, err)
					}
				}
				_, err := env.Client.CoreV1().ServiceAccounts(ns).Patch(ctx, saWorker, types.StrategicMergePatchType, []byte(`{"imagePullSecrets":[{"name":"audit-pull"}]}`), metav1.PatchOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "tls, dockerconfigjson, basic-auth, ssh-auth and opaque secrets are logged at Metadata without body", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "create", Resource: "secrets", Namespace: ns, NamePrefix: "audit-"},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, MinEvents: 5,
					},
					{
						Desc: "image pull secret attached to a service account is logged with body", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "patch", Resource: "serviceaccounts", Subresource: "-", Namespace: ns, Name: saWorker},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-pull"},
					},
				}
			},
		},

		// ==================================================================
		// Admission policy and API server configuration
		// ==================================================================
		{
			// Pod Security Admission: a denial in enforce mode, then the
			// namespace relaxed to privileged while audit mode stays
			// restricted, which makes PSA annotate the audit event of the
			// violating pod it now admits.
			Name:     "pod-security-admission",
			Optional: true,
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Name("psa")
				if _, err := env.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name: ns, Labels: map[string]string{"audit-test": env.RunID, psaEnforce: "restricted", psaAudit: "restricted"},
				}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// Pods cannot be created before the namespace's default SA exists.
				deadline := time.Now().Add(20 * time.Second)
				for {
					_, err := env.Client.CoreV1().ServiceAccounts(ns).Get(ctx, "default", metav1.GetOptions{})
					if err == nil {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("default service account of %s: %w", ns, err)
					}
					time.Sleep(time.Second)
				}
				p := sleepPod("psa-privileged", env.Image, nil)
				p.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				if _, err := env.Client.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected Pod Security to reject a privileged pod (is the PodSecurity admission plugin enabled?), got %v: %w", err, errNotInstalled)
				}
				if _, err := env.Client.CoreV1().Namespaces().Patch(ctx, ns, types.MergePatchType, []byte(`{"metadata":{"labels":{"`+psaEnforce+`":"privileged"}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("privileged pod after relaxing enforce: %w", err)
				}
				return env.Client.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Name("psa")
				pod := audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: "psa-privileged"}
				denied, admitted := pod, pod
				denied.ResponseCode, admitted.ResponseCode = 403, 201
				return []audit.Expect{
					{
						Desc: "namespace with Pod Security labels is logged with body", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "namespaces", Name: ns},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{psaEnforce},
					},
					{
						Desc: "relaxing Pod Security enforcement on a namespace is logged with the patch", Requirement: ReqIncident,
						Match: audit.Match{Verb: "patch", Resource: "namespaces", Name: ns},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"privileged"`},
					},
					{
						Desc: "privileged pod rejected by Pod Security is logged with body and the enforce-policy annotation", Requirement: ReqPrivileged,
						Match: denied, Level: "RequestResponse", Code: 403, RequestBody: audit.Required, RequestBodyContains: []string{`"privileged":true`},
						AnnotationsPresent: []string{"pod-security.kubernetes.io/enforce-policy"},
					},
					{
						Desc: "privileged pod admitted under audit=restricted carries the audit-violations annotation", Requirement: ReqPrivileged,
						Match: admitted, Level: "RequestResponse", AnnotationsPresent: []string{psaViolation},
					},
				}
			},
		},
		{
			// ValidatingAdmissionPolicy with validationActions [Audit]: the
			// request is admitted and the policy's verdict is written into
			// the audit event as an annotation, and nowhere else.
			Name:     "validating-admission-policy-audit",
			Optional: true,
			Act: func(ctx context.Context, env *audit.Env) error {
				vap := env.Client.AdmissionregistrationV1()
				fail := admissionv1.Fail
				if _, err := vap.ValidatingAdmissionPolicies().Create(ctx, &admissionv1.ValidatingAdmissionPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: env.Name("vap")},
					Spec: admissionv1.ValidatingAdmissionPolicySpec{
						FailurePolicy: &fail,
						MatchConstraints: &admissionv1.MatchResources{ResourceRules: []admissionv1.NamedRuleWithOperations{{
							RuleWithOperations: admissionv1.RuleWithOperations{
								Operations: []admissionv1.OperationType{admissionv1.Create},
								Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}},
							},
						}}},
						Validations: []admissionv1.Validation{{Expression: `!object.metadata.name.startsWith("vap-violator")`, Message: "audit-test violation"}},
					},
				}, metav1.CreateOptions{}); err != nil {
					if apierrors.IsNotFound(err) {
						return fmt.Errorf("ValidatingAdmissionPolicy: %w", errNotInstalled)
					}
					return err
				}
				if _, err := vap.ValidatingAdmissionPolicyBindings().Create(ctx, &admissionv1.ValidatingAdmissionPolicyBinding{
					ObjectMeta: metav1.ObjectMeta{Name: env.Name("vap")},
					Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
						PolicyName:        env.Name("vap"),
						ValidationActions: []admissionv1.ValidationAction{admissionv1.Audit},
						MatchResources:    &admissionv1.MatchResources{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"audit-test": env.RunID}}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// The policy takes a moment to be compiled and picked up.
				time.Sleep(5 * time.Second)
				for i := 1; i <= 3; i++ {
					if _, err := env.Client.CoreV1().ConfigMaps(env.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("vap-violator-%d", i)}}, metav1.CreateOptions{}); err != nil {
						return err
					}
					time.Sleep(2 * time.Second)
				}
				if err := vap.ValidatingAdmissionPolicyBindings().Delete(ctx, env.Name("vap"), metav1.DeleteOptions{}); err != nil {
					return err
				}
				return vap.ValidatingAdmissionPolicies().Delete(ctx, env.Name("vap"), metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				g := "admissionregistration.k8s.io"
				return []audit.Expect{
					{Desc: "ValidatingAdmissionPolicy create is logged with its CEL rule", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: g, Resource: "validatingadmissionpolicies", Name: env.Name("vap")}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"vap-violator"}, Gap: gapNonCoreBody},
					{Desc: "ValidatingAdmissionPolicyBinding create is logged with its actions", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: g, Resource: "validatingadmissionpolicybindings", Name: env.Name("vap")}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"Audit"`}, Gap: gapNonCoreBody},
					{Desc: "policy and binding deletes are logged", Requirement: ReqEcosystem, Match: audit.Match{Verb: "delete", Group: g, Name: env.Name("vap")}, Level: "Metadata", MinEvents: 2},
					{
						Desc: "a request failing an Audit-mode policy carries the validation_failure annotation", Requirement: ReqEcosystem,
						Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: env.Namespace, Name: "vap-violator-3"},
						Level: "Metadata", AnnotationsPresent: []string{vapFailure},
					},
				}
			},
		},
		{
			// Registering an aggregated API routes a whole API group to a
			// service of your choosing. Sent as a dry-run, so discovery never
			// sees an unavailable APIService.
			Name: "apiservice-registration",
			Act: func(ctx context.Context, env *audit.Env) error {
				gvr := schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}
				group := "agg." + env.Domain
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService",
					"metadata": map[string]any{"name": "v1." + group},
					"spec": map[string]any{
						"group": group, "version": "v1", "groupPriorityMinimum": int64(1000), "versionPriority": int64(15),
						"insecureSkipTLSVerify": true,
						"service":               map[string]any{"namespace": env.Namespace, "name": "audit-svc", "port": int64(443)},
					},
				}}
				_, err := env.Dynamic.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				m := audit.Match{Verb: "create", Group: "apiregistration.k8s.io", Resource: "apiservices", Name: "v1.agg." + env.Domain, URIContains: "dryRun=All"}
				return []audit.Expect{
					{Desc: "APIService registration is logged (any level)", Requirement: ReqEcosystem, Match: m, MinEvents: 1},
					{Desc: "APIService registration is logged with the target service and insecureSkipTLSVerify", Requirement: ReqIncident, Match: m, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"insecureSkipTLSVerify", "audit-svc"}, Gap: gapNonCoreBody},
				}
			},
		},
		{
			// API Priority and Fairness decides whose requests the API server
			// serves under load; a FlowSchema can starve a client, audit log
			// shippers included. This one matches a user that does not exist.
			Name: "flowcontrol-apf",
			Act: func(ctx context.Context, env *audit.Env) error {
				fc := env.Client.FlowcontrolV1()
				name := env.Name("apf")
				if _, err := fc.PriorityLevelConfigurations().Create(ctx, &flowcontrolv1.PriorityLevelConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: flowcontrolv1.PriorityLevelConfigurationSpec{
						Type: flowcontrolv1.PriorityLevelEnablementLimited,
						Limited: &flowcontrolv1.LimitedPriorityLevelConfiguration{
							NominalConcurrencyShares: int32p(1),
							LimitResponse:            flowcontrolv1.LimitResponse{Type: flowcontrolv1.LimitResponseTypeReject},
						},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := fc.FlowSchemas().Create(ctx, &flowcontrolv1.FlowSchema{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: flowcontrolv1.FlowSchemaSpec{
						PriorityLevelConfiguration: flowcontrolv1.PriorityLevelConfigurationReference{Name: name},
						MatchingPrecedence:         9000,
						Rules: []flowcontrolv1.PolicyRulesWithSubjects{{
							Subjects:         []flowcontrolv1.Subject{{Kind: flowcontrolv1.SubjectKindUser, User: &flowcontrolv1.UserSubject{Name: "audit-nobody-" + env.RunID}}},
							NonResourceRules: []flowcontrolv1.NonResourcePolicyRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/audit-test-nothing"}}},
						}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := fc.FlowSchemas().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				return fc.PriorityLevelConfigurations().Delete(ctx, name, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				g := "flowcontrol.apiserver.k8s.io"
				name := env.Name("apf")
				return []audit.Expect{
					{Desc: "PriorityLevelConfiguration create is logged with body", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: g, Resource: "prioritylevelconfigurations", Name: name}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "FlowSchema create is logged with the subjects it matches", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: g, Resource: "flowschemas", Name: name}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-nobody-" + env.RunID}, Gap: gapNonCoreBody},
					{Desc: "FlowSchema and priority level deletes are logged", Requirement: ReqEcosystem, Match: audit.Match{Verb: "delete", Group: g, Name: name}, Level: "Metadata", MinEvents: 2},
				}
			},
		},
		{
			// Networking objects outside the policy's core group that charts
			// install: an IngressClass, an ingress with the annotations that
			// switch security features of ingress-nginx, and hand-written
			// endpoints that point a service anywhere.
			Name: "ingress-and-endpoints",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				class := env.Name("ic")
				if _, err := env.Client.NetworkingV1().IngressClasses().Create(ctx, &networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{Name: class},
					Spec:       networkingv1.IngressClassSpec{Controller: env.Label("none")},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				pt := networkingv1.PathTypePrefix
				if _, err := env.Client.NetworkingV1().Ingresses(ns).Create(ctx, &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-annotated", Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/whitelist-source-range": "0.0.0.0/0",
						"nginx.ingress.kubernetes.io/ssl-redirect":           "false",
						"nginx.ingress.kubernetes.io/auth-url":               "https://auth.example.invalid/" + env.RunID,
					}},
					Spec: networkingv1.IngressSpec{IngressClassName: &class, Rules: []networkingv1.IngressRule{{
						Host: "annotated-" + env.RunID + ".example.invalid",
						IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
							Path: "/", PathType: &pt,
							Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "audit-svc", Port: networkingv1.ServiceBackendPort{Number: 80}}},
						}}}},
					}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.NetworkingV1().Ingresses(ns).Patch(ctx, "audit-annotated", types.MergePatchType,
					[]byte(`{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/auth-url":null}}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().Services(ns).Create(ctx, &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-external"},
					Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().Endpoints(ns).Create(ctx, &corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-external"},
					Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "192.0.2.10"}}, Ports: []corev1.EndpointPort{{Port: 80}}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.DiscoveryV1().EndpointSlices(ns).Create(ctx, &discoveryv1.EndpointSlice{
					ObjectMeta:  metav1.ObjectMeta{Name: "audit-external-manual", Labels: map[string]string{discoveryv1.LabelServiceName: "audit-external"}},
					AddressType: discoveryv1.AddressTypeIPv4,
					Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.11"}}},
					Ports:       []discoveryv1.EndpointPort{{Port: int32p(80)}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Client.NetworkingV1().IngressClasses().Delete(ctx, class, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "IngressClass create is logged with body", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: "networking.k8s.io", Resource: "ingressclasses", Name: env.Name("ic")}, Level: "Request", RequestBody: audit.Required, Gap: gapNonCoreBody},
					{Desc: "ingress with security annotations is logged with them", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: "networking.k8s.io", Resource: "ingresses", Namespace: ns, Name: "audit-annotated"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"whitelist-source-range", "auth-url"}, Gap: gapNonCoreBody},
					{Desc: "removing an ingress auth annotation is logged with the patch", Requirement: ReqIncident, Match: audit.Match{Verb: "patch", Group: "networking.k8s.io", Resource: "ingresses", Namespace: ns, Name: "audit-annotated"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"nginx.ingress.kubernetes.io/auth-url":null`}, Gap: gapNonCoreBody},
					{Desc: "ingress changes are logged (any level)", Requirement: ReqEcosystem, Match: audit.Match{Verbs: []string{"create", "patch"}, Group: "networking.k8s.io", Resource: "ingresses", Namespace: ns, Name: "audit-annotated"}, MinEvents: 2},
					{Desc: "hand-written Endpoints are logged with the target address", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Resource: "endpoints", Namespace: ns, Name: "audit-external"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"192.0.2.10"}},
					{Desc: "hand-written EndpointSlice is logged with the target address", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: "discovery.k8s.io", Resource: "endpointslices", Namespace: ns, Name: "audit-external-manual"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"192.0.2.11"}, Gap: gapNonCoreBody},
				}
			},
		},
		{
			// A CSI driver object tells kubelets how to treat a driver's
			// volumes (whether to pass pod service account tokens to it, for
			// one). This one names a driver nothing runs.
			Name: "storage-csidriver",
			Act: func(ctx context.Context, env *audit.Env) error {
				name := env.Name("csi")
				if _, err := env.Client.StorageV1().CSIDrivers().Create(ctx, &storagev1.CSIDriver{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: storagev1.CSIDriverSpec{
						AttachRequired: boolp(false),
						TokenRequests:  []storagev1.TokenRequest{{Audience: "audit-" + env.RunID}},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Client.StorageV1().CSIDrivers().Delete(ctx, name, metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				m := audit.Match{Group: "storage.k8s.io", Resource: "csidrivers", Name: env.Name("csi")}
				create, del := m, m
				create.Verb, del.Verb = "create", "delete"
				return []audit.Expect{
					{Desc: "CSIDriver create is logged with its token requests", Requirement: ReqEcosystem, Match: create, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-" + env.RunID}, Gap: gapNonCoreBody},
					{Desc: "CSIDriver delete is logged", Requirement: ReqEcosystem, Match: del, Level: "Metadata"},
				}
			},
		},
		{
			// Day-2 kubectl work: rollout restart, set image, a cordon sent as
			// a dry-run (so no real node is cordoned) and kubectl cp, which is
			// an exec of tar.
			Name: "kubectl-day2-operations",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				deps := env.Client.AppsV1().Deployments(ns)
				labels := map[string]string{"app": "day2"}
				tmpl := sleepPod("", env.Image, labels)
				if _, err := deps.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "day2"},
					Spec: appsv1.DeploymentSpec{Replicas: int32p(0), Selector: &metav1.LabelSelector{MatchLabels: labels},
						Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: tmpl.Spec}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				restart := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().Format(time.RFC3339))
				if _, err := deps.Patch(ctx, "day2", types.StrategicMergePatchType, []byte(restart), metav1.PatchOptions{}); err != nil {
					return err
				}
				setImage := `{"spec":{"template":{"spec":{"containers":[{"name":"main","image":"` + env.Image + `-audit-set-image"}]}}}}`
				if _, err := deps.Patch(ctx, "day2", types.StrategicMergePatchType, []byte(setImage), metav1.PatchOptions{}); err != nil {
					return err
				}
				if err := deps.Delete(ctx, "day2", metav1.DeleteOptions{}); err != nil {
					return err
				}
				plain, err := env.Client.CoreV1().Pods(ns).Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if _, err := env.Client.CoreV1().Nodes().Patch(ctx, plain.Spec.NodeName, types.StrategicMergePatchType,
					[]byte(`{"spec":{"unschedulable":true}}`), metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
					return fmt.Errorf("dry-run cordon: %w", err)
				}
				req := env.Client.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(podPlain).SubResource("exec").
					VersionedParams(&corev1.PodExecOptions{Command: []string{"tar", "cf", "-", "/etc/hostname"}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
				ex, err := remotecommand.NewSPDYExecutor(env.ConfigFor(nil), "POST", req.URL())
				if err != nil {
					return err
				}
				return ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				dep := audit.Match{Verb: "patch", Group: "apps", Resource: "deployments", Namespace: ns, Name: "day2"}
				return []audit.Expect{
					{Desc: "kubectl rollout restart and set image are logged (any level)", Requirement: ReqHumans, Match: dep, MinEvents: 2},
					{Desc: "kubectl rollout restart / set image are logged with the patch", Requirement: ReqHumans, Match: dep, Level: "Request", RequestBody: audit.Required, SomeRequestBodyContains: []string{"kubectl.kubernetes.io/restartedAt", "-audit-set-image"}, Gap: gapNonCoreBody},
					{Desc: "kubectl cordon (dry-run) is logged with the node patch", Requirement: ReqHumans, Match: audit.Match{Verb: "patch", Resource: "nodes", Subresource: "-", URIContains: "dryRun=All"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"unschedulable":true`}},
					{Desc: "kubectl cp (exec of tar) is logged with the command in the URI", Requirement: ReqExec, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: ns, Name: podPlain, URIContains: "command=tar"}, Level: "Request"},
				}
			},
		},
		{
			// cert-manager: an Issuer and a Certificate, created for real in
			// the test namespace, so cert-manager itself writes the key pair
			// into a Secret. The key must not reach the log.
			Name:     "operator-cert-manager",
			Optional: true,
			Act: func(ctx context.Context, env *audit.Env) error {
				version, err := servedVersion(env, "cert-manager.io")
				if err != nil {
					return err
				}
				ns := env.Namespace
				res := func(r string) dynamicNS {
					return env.Dynamic.Resource(schema.GroupVersionResource{Group: "cert-manager.io", Version: version, Resource: r}).Namespace(ns)
				}
				apiVersion := "cert-manager.io/" + version
				if _, err := res("issuers").Create(ctx, &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": apiVersion, "kind": "Issuer",
					"metadata": map[string]any{"name": "audit-selfsigned"},
					"spec":     map[string]any{"selfSigned": map[string]any{}},
				}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := res("certificates").Create(ctx, &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": apiVersion, "kind": "Certificate",
					"metadata": map[string]any{"name": "audit-cert"},
					"spec": map[string]any{
						"secretName": "audit-cert-tls", "commonName": "audit-" + env.RunID + ".example.invalid",
						"dnsNames":  []any{"audit-" + env.RunID + ".example.invalid"},
						"issuerRef": map[string]any{"name": "audit-selfsigned", "kind": "Issuer"},
					},
				}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				deadline := time.Now().Add(45 * time.Second)
				for {
					if _, err := env.Client.CoreV1().Secrets(ns).Get(ctx, "audit-cert-tls", metav1.GetOptions{}); err == nil {
						return nil
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("cert-manager did not issue audit-cert-tls within 45s")
					}
					time.Sleep(2 * time.Second)
				}
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "cert-manager Issuer create is logged (any level)", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: "cert-manager.io", Resource: "issuers", Namespace: ns, Name: "audit-selfsigned"}, MinEvents: 1},
					{Desc: "cert-manager Certificate create is logged with body", Requirement: ReqEcosystem, Match: audit.Match{Verb: "create", Group: "cert-manager.io", Resource: "certificates", Namespace: ns, Name: "audit-cert"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-cert-tls"}, Gap: gapNonCoreBody},
					{
						Desc: "the certificate secret written by cert-manager is logged at Metadata without the key", Requirement: ReqSecrets,
						Match: audit.Match{Verbs: []string{"create", "update", "patch"}, Resource: "secrets", Namespace: ns, Name: "audit-cert-tls", UserPrefix: "system:serviceaccount:", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
					{
						Desc: "cert-manager CertificateRequest (created by the controller) is logged", Requirement: ReqEcosystem,
						Match:     audit.Match{Verb: "create", Group: "cert-manager.io", Resource: "certificaterequests", Namespace: ns, AnyUA: true},
						MinEvents: 1,
					},
				}
			},
		},
	}
}

// operatorScenarios are the dry-run custom resource checks of the common
// operators and add-ons. Each is skipped when its API group is not served.
func operatorScenarios() []Scenario {
	never := map[string]any{"matchLabels": map[string]any{"audit-test": "nothing"}}
	return []Scenario{
		operatorScenario("operator-prometheus", "monitoring.coreos.com", nil, []opObject{
			{resource: "servicemonitors", kind: "ServiceMonitor", spec: map[string]any{"selector": never, "endpoints": []any{map[string]any{"port": "metrics"}}}},
			{resource: "prometheusrules", kind: "PrometheusRule", spec: map[string]any{"groups": []any{map[string]any{"name": "audit", "rules": []any{map[string]any{"alert": "AuditTest", "expr": "vector(0) > 1"}}}}}},
		}),
		operatorScenario("operator-argocd", "argoproj.io", []string{"argocd", "argo-cd", "openshift-gitops"}, []opObject{
			{resource: "appprojects", kind: "AppProject", spec: map[string]any{"sourceRepos": []any{"*"}, "destinations": []any{map[string]any{"server": "*", "namespace": "*"}}, "clusterResourceWhitelist": []any{map[string]any{"group": "*", "kind": "*"}}}},
			{resource: "applications", kind: "Application", spec: map[string]any{
				"project":     "default",
				"source":      map[string]any{"repoURL": "https://git.example.invalid/audit.git", "path": ".", "targetRevision": "HEAD"},
				"destination": map[string]any{"server": "https://kubernetes.default.svc", "namespace": "audit-nowhere"},
			}},
		}),
		operatorScenario("operator-flux", "source.toolkit.fluxcd.io", nil, []opObject{
			{resource: "gitrepositories", kind: "GitRepository", spec: map[string]any{"interval": "10m", "url": "https://git.example.invalid/audit.git", "ref": map[string]any{"branch": "main"}}},
		}),
		operatorScenario("operator-flux-kustomize", "kustomize.toolkit.fluxcd.io", nil, []opObject{
			{resource: "kustomizations", kind: "Kustomization", spec: map[string]any{"interval": "10m", "path": "./", "prune": true, "sourceRef": map[string]any{"kind": "GitRepository", "name": "audit-gitrepository"}}},
		}),
		operatorScenario("policy-engine-kyverno", "kyverno.io", nil, []opObject{
			{resource: "clusterpolicies", kind: "ClusterPolicy", cluster: true, spec: map[string]any{
				"validationFailureAction": "Audit", "background": false,
				"rules": []any{map[string]any{
					"name":     "audit-test",
					"match":    map[string]any{"any": []any{map[string]any{"resources": map[string]any{"kinds": []any{"ConfigMap"}, "selector": never}}}},
					"validate": map[string]any{"message": "audit-test", "pattern": map[string]any{"metadata": map[string]any{"name": "?*"}}},
				}},
			}},
		}),
		operatorScenario("policy-engine-gatekeeper", "templates.gatekeeper.sh", nil, []opObject{
			{resource: "constrainttemplates", kind: "ConstraintTemplate", cluster: true, spec: map[string]any{
				"crd":     map[string]any{"spec": map[string]any{"names": map[string]any{"kind": "AuditTestNothing"}}},
				"targets": []any{map[string]any{"target": "admission.k8s.gatekeeper.sh", "rego": "package audittestnothing\nviolation[{\"msg\": \"never\"}] { false }\n"}},
			}},
		}),
		operatorScenario("operator-external-secrets", "external-secrets.io", nil, []opObject{
			{resource: "secretstores", kind: "SecretStore", spec: map[string]any{"provider": map[string]any{"kubernetes": map[string]any{
				"remoteNamespace": "default", "server": map[string]any{"caProvider": map[string]any{"type": "ConfigMap", "name": "kube-root-ca.crt", "key": "ca.crt"}},
				"auth": map[string]any{"serviceAccount": map[string]any{"name": saWorker}},
			}}}},
			{resource: "externalsecrets", kind: "ExternalSecret", spec: map[string]any{
				"refreshInterval": "1h", "secretStoreRef": map[string]any{"name": "audit-secretstore", "kind": "SecretStore"},
				"target": map[string]any{"name": "audit-synced"}, "dataFrom": []any{map[string]any{"extract": map[string]any{"key": "audit-nothing"}}},
			}},
		}),
		operatorScenario("operator-sealed-secrets", "bitnami.com", nil, []opObject{
			{resource: "sealedsecrets", kind: "SealedSecret", spec: map[string]any{"encryptedData": map[string]any{"password": "AgBy3i4OJSWK+PiTySYZZA9rO43cGDEq"}, "template": map[string]any{"type": "Opaque"}}},
		}),
		operatorScenario("operator-velero", "velero.io", []string{"velero", "openshift-adp"}, []opObject{
			{resource: "backups", kind: "Backup", spec: map[string]any{"includedNamespaces": []any{"*"}, "ttl": "1h0m0s"}},
			{resource: "restores", kind: "Restore", spec: map[string]any{"backupName": "audit-nothing"}},
		}),
		operatorScenario("service-mesh-istio", "security.istio.io", nil, []opObject{
			{resource: "authorizationpolicies", kind: "AuthorizationPolicy", spec: map[string]any{"selector": never, "action": "ALLOW", "rules": []any{map[string]any{}}}},
			{resource: "peerauthentications", kind: "PeerAuthentication", spec: map[string]any{"selector": never, "mtls": map[string]any{"mode": "PERMISSIVE"}}},
		}),
		operatorScenario("cni-cilium", "cilium.io", nil, []opObject{
			{resource: "ciliumnetworkpolicies", kind: "CiliumNetworkPolicy", spec: map[string]any{"endpointSelector": never, "ingress": []any{map[string]any{"fromEntities": []any{"world"}}}}},
		}),
		operatorScenario("gateway-api", "gateway.networking.k8s.io", nil, []opObject{
			{resource: "httproutes", kind: "HTTPRoute", spec: map[string]any{
				"parentRefs": []any{map[string]any{"name": "audit-nothing"}},
				"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "audit-svc", "port": int64(80)}}}},
			}},
		}),
		operatorScenario("ingress-traefik", "traefik.io", nil, []opObject{
			{resource: "middlewares", kind: "Middleware", spec: map[string]any{"ipAllowList": map[string]any{"sourceRange": []any{"0.0.0.0/0"}}}},
		}),
		operatorScenario("storage-snapshots", "snapshot.storage.k8s.io", nil, []opObject{
			{resource: "volumesnapshotclasses", kind: "VolumeSnapshotClass", cluster: true, spec: nil},
		}),
	}
}

// cleanupEcosystem removes what the ecosystem scenarios may leave behind
// after an aborted run; namespaced objects go with the test namespace.
func cleanupEcosystem(ctx context.Context, env *audit.Env, try func(string, error)) {
	c := env.Client
	del := metav1.DeleteOptions{}
	try("psa namespace", c.CoreV1().Namespaces().Delete(ctx, env.Name("psa"), del))
	try("helm kube-system configmap", c.CoreV1().ConfigMaps("kube-system").Delete(ctx, env.Name("helm")+".v1", del))
	try("aggregated clusterrole", c.RbacV1().ClusterRoles().Delete(ctx, env.Name("agg-child"), del))
	try("aggregating clusterrole", c.RbacV1().ClusterRoles().Delete(ctx, env.Name("agg-parent"), del))
	try("validatingadmissionpolicybinding", c.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, env.Name("vap"), del))
	try("validatingadmissionpolicy", c.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(ctx, env.Name("vap"), del))
	try("flowschema", c.FlowcontrolV1().FlowSchemas().Delete(ctx, env.Name("apf"), del))
	try("prioritylevelconfiguration", c.FlowcontrolV1().PriorityLevelConfigurations().Delete(ctx, env.Name("apf"), del))
	try("ingressclass", c.NetworkingV1().IngressClasses().Delete(ctx, env.Name("ic"), del))
	try("csidriver", c.StorageV1().CSIDrivers().Delete(ctx, env.Name("csi"), del))
}
