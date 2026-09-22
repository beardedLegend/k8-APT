package scenarios

// Edge-case scenarios: normal day-to-day usage that the base scenarios do not
// cover (batch workloads, server-side apply, dry-run, pagination, log
// streaming, leases, custom resources), error paths (400/404/405/409/415/422),
// odd but real request shapes (HEAD and OPTIONS probes, basic auth, tokens of
// deleted accounts, malformed impersonation, RBAC escalation prevention) and
// the noise that must stay out of the log while all of that happens.
//
// Every scenario lives in the test namespace or creates uniquely named
// objects that it deletes itself; cleanupEdge sweeps what an aborted run may
// leave behind.

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/retry"

	"github.com/your-org/k8-apt/internal/audit"
)

const (
	ReqEdge   = "R15 edge cases: error paths, dry-run, apply, odd HTTP requests"
	ReqBudget = "R16 log volume: idle cluster fits the yearly budget"
)

const (
	podSecretConsumer = "secret-consumer"
	podManualBind     = "manual-bind"
	secretMounted     = "mounted"
	edgeCRDResource   = "edgetests"
	decisionKey       = "authorization.k8s.io/decision"
)

var forbidAnn = map[string]string{decisionKey: "forbid"}
var allowAnn = map[string]string{decisionKey: "allow"}

// tokenConfig returns the run config authenticating with a bearer token
// instead of the admin certificate.
func tokenConfig(env *audit.Env, token string) *rest.Config {
	return env.ConfigFor(func(c *rest.Config) {
		c.TLSClientConfig.CertData, c.TLSClientConfig.KeyData = nil, nil
		c.TLSClientConfig.CertFile, c.TLSClientConfig.KeyFile = "", ""
		c.BearerToken = token
		c.BearerTokenFile = ""
	})
}

func dynamicWithToken(env *audit.Env, token string) (dynamic.Interface, error) {
	return dynamic.NewForConfig(tokenConfig(env, token))
}

// untilAllowed retries f while it fails with 403, for the RBAC authorizer to
// observe a binding that was created a moment ago.
func untilAllowed(ctx context.Context, timeout time.Duration, f func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := f()
		if !apierrors.IsForbidden(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Second)
	}
}

func saUser(ns, sa string) string { return "system:serviceaccount:" + ns + ":" + sa }

func edgeCRD(env *audit.Env) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": edgeCRDName(env), "labels": map[string]any{"audit-test": env.RunID}},
		"spec": map[string]any{
			"group": env.Domain, "scope": "Namespaced",
			"names": map[string]any{"plural": edgeCRDResource, "singular": "edgetest", "kind": "EdgeTest"},
			"versions": []any{map[string]any{
				"name": "v1", "served": true, "storage": true,
				"subresources": map[string]any{"status": map[string]any{}},
				"schema":       map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}},
			}},
		},
	}}
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

// edgeCRDName / edgeGVR name the CRD the custom-resources scenario creates,
// in the run's own test domain.
func edgeCRDName(env *audit.Env) string { return edgeCRDResource + "." + env.Domain }

func edgeGVR(env *audit.Env) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: env.Domain, Version: "v1", Resource: edgeCRDResource}
}

func EdgeScenarios() []Scenario {
	return []Scenario{
		// ==================================================================
		// Normal usage
		// ==================================================================
		{
			Name: "job-cronjob-lifecycle",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				jobs := env.Client.BatchV1().Jobs(ns)
				job := &batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-job"},
					Spec: batchv1.JobSpec{
						BackoffLimit: int32p(0),
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"audit-test": "job"}},
							Spec: corev1.PodSpec{
								RestartPolicy: corev1.RestartPolicyNever,
								Containers:    []corev1.Container{{Name: "main", Image: env.Image, Command: []string{"true"}}},
							},
						},
					},
				}
				if _, err := jobs.Create(ctx, job, metav1.CreateOptions{}); err != nil {
					return err
				}
				// Wait for the job-controller to create the pod.
				deadline := time.Now().Add(60 * time.Second)
				for {
					pods, err := env.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: "job-name=audit-job"})
					if err != nil {
						return err
					}
					if len(pods.Items) > 0 || time.Now().After(deadline) {
						break
					}
					time.Sleep(2 * time.Second)
				}
				cjs := env.Client.BatchV1().CronJobs(ns)
				if _, err := cjs.Create(ctx, &batchv1.CronJob{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-cronjob"},
					Spec: batchv1.CronJobSpec{
						Schedule: "* * * * *", Suspend: boolp(true),
						JobTemplate: batchv1.JobTemplateSpec{Spec: job.Spec},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := cjs.Patch(ctx, "audit-cronjob", types.MergePatchType, []byte(`{"spec":{"schedule":"0 0 1 1 *"}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				bg := metav1.DeletePropagationBackground
				if err := cjs.Delete(ctx, "audit-cronjob", metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil {
					return err
				}
				return jobs.Delete(ctx, "audit-job", metav1.DeleteOptions{PropagationPolicy: &bg})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "job create with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: "batch", Resource: "jobs", Subresource: "-", Namespace: ns, Name: "audit-job"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{env.Image}},
					{Desc: "cronjob create with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: "batch", Resource: "cronjobs", Namespace: ns, Name: "audit-cronjob"}, Level: "Request", RequestBody: audit.Required},
					{Desc: "cronjob patch with patch body", Requirement: ReqResources, Match: audit.Match{Verb: "patch", Group: "batch", Resource: "cronjobs", Namespace: ns, Name: "audit-cronjob"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"0 0 1 1 *"}},
					{Desc: "job delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: "batch", Resource: "jobs", Namespace: ns, Name: "audit-job"}, Level: "Request"},
					{Desc: "cronjob delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: "batch", Resource: "cronjobs", Namespace: ns, Name: "audit-cronjob"}, Level: "Request"},
					{
						Desc: "pod created by the job-controller is Metadata only", Requirement: ReqNoise,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, User: saUser("kube-system", "job-controller"), AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
					{
						Desc: "job-controller pod patches (tracking finalizer) are Metadata without body", Requirement: ReqNoise,
						Match: audit.Match{Verb: "patch", Resource: "pods", Namespace: ns, User: saUser("kube-system", "job-controller"), AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true,
					},
					{
						Desc: "job status updates by the job-controller are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Group: "batch", Resource: "jobs", Subresource: "status", Namespace: ns, AnyUA: true},
						Level: "None",
					},
				}
			},
		},
		{
			Name: "workload-controllers",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				labels := map[string]string{"app": "audit-sts"}
				tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: sleepPod("", env.Image, labels).Spec}
				// Never schedulable: the HPA has a target but no pod ever runs.
				tmpl.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				if _, err := env.Client.AppsV1().StatefulSets(ns).Create(ctx, &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-sts"},
					Spec: appsv1.StatefulSetSpec{
						Replicas: int32p(1), ServiceName: "audit-svc",
						Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: tmpl,
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				dsLabels := map[string]string{"app": "audit-ds"}
				dsTmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: dsLabels}, Spec: sleepPod("", env.Image, dsLabels).Spec}
				// Impossible nodeSelector: the DaemonSet never schedules a pod.
				dsTmpl.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				if _, err := env.Client.AppsV1().DaemonSets(ns).Create(ctx, &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-ds"},
					Spec:       appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: dsLabels}, Template: dsTmpl},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := env.Client.AutoscalingV2().HorizontalPodAutoscalers(ns).Create(ctx, &autoscalingv2.HorizontalPodAutoscaler{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-hpa"},
					Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
						ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "audit-sts"},
						MinReplicas:    int32p(1), MaxReplicas: 2,
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// Give the controllers a moment to write status before deleting.
				time.Sleep(3 * time.Second)
				if err := env.Client.AutoscalingV2().HorizontalPodAutoscalers(ns).Delete(ctx, "audit-hpa", metav1.DeleteOptions{}); err != nil {
					return err
				}
				if err := env.Client.AppsV1().DaemonSets(ns).Delete(ctx, "audit-ds", metav1.DeleteOptions{}); err != nil {
					return err
				}
				return env.Client.AppsV1().StatefulSets(ns).Delete(ctx, "audit-sts", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				var out []audit.Expect
				for _, r := range []struct{ group, res, name string }{
					{"apps", "statefulsets", "audit-sts"},
					{"apps", "daemonsets", "audit-ds"},
					{"autoscaling", "horizontalpodautoscalers", "audit-hpa"},
				} {
					out = append(out,
						audit.Expect{Desc: r.res + " create with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: r.group, Resource: r.res, Subresource: "-", Namespace: ns, Name: r.name}, Level: "Request", RequestBody: audit.Required},
						audit.Expect{Desc: r.res + " delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: r.group, Resource: r.res, Namespace: ns, Name: r.name}, Level: "Request"},
						audit.Expect{Desc: r.res + " status updates by controllers are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"update", "patch"}, Group: r.group, Resource: r.res, Subresource: "status", Namespace: ns, AnyUA: true}, Level: "None"},
					)
				}
				return out
			},
		},
		{
			// kubectl apply --server-side sends an apply patch: creation and
			// update are both verb "patch", and the body is the applied object.
			Name: "server-side-apply",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				opts := metav1.PatchOptions{FieldManager: "audit-policy-test", Force: boolp(true)}
				marker := "audit-ssa-" + env.RunID
				deploy := func(replicas int) []byte {
					return []byte(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"ssa-deploy","labels":{"audit-ssa":"%s"}},"spec":{"replicas":%d,"selector":{"matchLabels":{"app":"ssa-deploy"}},"template":{"metadata":{"labels":{"app":"ssa-deploy"}},"spec":{"terminationGracePeriodSeconds":1,"containers":[{"name":"main","image":"%s","command":["sh","-c","sleep 3600"]}]}}}}`, marker, replicas, env.Image))
				}
				d := env.Client.AppsV1().Deployments(ns)
				if _, err := d.Patch(ctx, "ssa-deploy", types.ApplyPatchType, deploy(1), opts); err != nil {
					return fmt.Errorf("apply deployment: %w", err)
				}
				if _, err := d.Patch(ctx, "ssa-deploy", types.ApplyPatchType, deploy(0), opts); err != nil {
					return fmt.Errorf("re-apply deployment: %w", err)
				}
				if _, err := env.Client.CoreV1().ConfigMaps(ns).Patch(ctx, "ssa-cm", types.ApplyPatchType,
					[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"ssa-cm"},"data":{"setting":"`+marker+`"}}`), opts); err != nil {
					return fmt.Errorf("apply configmap: %w", err)
				}
				value := "SSA-SECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("server-side-applied secret value", value)
				env.AddMarker("server-side-applied secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value)))
				if _, err := env.Client.CoreV1().Secrets(ns).Patch(ctx, "ssa-secret", types.ApplyPatchType,
					[]byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"ssa-secret"},"stringData":{"password":"`+value+`"}}`), opts); err != nil {
					return fmt.Errorf("apply secret: %w", err)
				}
				return d.Delete(ctx, "ssa-deploy", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				marker := "audit-ssa-" + env.RunID
				return []audit.Expect{
					{
						Desc: "server-side apply of a deployment is verb patch at Request with the applied object", Requirement: ReqEdge,
						Match: audit.Match{Verb: "patch", Group: "apps", Resource: "deployments", Namespace: ns, Name: "ssa-deploy"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{marker, env.Image}, MinEvents: 2,
					},
					{
						Desc: "an object created through apply produces no create event", Requirement: ReqEdge,
						Match: audit.Match{Verb: "create", Group: "apps", Resource: "deployments", Namespace: ns, Name: "ssa-deploy"},
						Level: "None",
					},
					{
						Desc: "server-side apply of a configmap is Metadata without body", Requirement: ReqResources,
						Match: audit.Match{Verb: "patch", Resource: "configmaps", Namespace: ns, Name: "ssa-cm"},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
					{
						Desc: "server-side apply of a secret is Metadata without body", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "patch", Resource: "secrets", Namespace: ns, Name: "ssa-secret"},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
				}
			},
		},
		{
			// kubectl apply --dry-run=server: nothing persists, but the intent
			// (a privileged pod, a deletion) is visible with dryRun in the URI.
			Name: "dry-run",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				pods := env.Client.CoreV1().Pods(ns)
				p := sleepPod("dryrun-priv", env.Image, nil)
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolp(true)}
				if _, err := pods.Create(ctx, p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
					return fmt.Errorf("dry-run create: %w", err)
				}
				if _, err := pods.Get(ctx, "dryrun-priv", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
					return fmt.Errorf("dry-run pod exists after dry-run create: %v", err)
				}
				if err := pods.Delete(ctx, podPlain, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
					return fmt.Errorf("dry-run delete: %w", err)
				}
				if _, err := pods.Get(ctx, podPlain, metav1.GetOptions{}); err != nil {
					return fmt.Errorf("plain pod gone after dry-run delete: %w", err)
				}
				value := "DRYRUN-SECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("dry-run secret value", value)
				env.AddMarker("dry-run secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value)))
				_, err := env.Client.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "dryrun-secret"}, StringData: map[string]string{"password": value},
				}, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "dry-run create of a privileged pod is logged with body and dryRun in the URI", Requirement: ReqEdge,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: "dryrun-priv"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"privileged":true`}, Code: 201,
					},
					{
						Desc: "dry-run create carries dryRun=All in the request URI", Requirement: ReqEdge,
						Match: audit.Match{Verb: "create", Resource: "pods", Namespace: ns, Name: "dryrun-priv", URIContains: "dryRun=All"},
						Level: "Request",
					},
					{
						// client-go sends DeleteOptions in the body, so a dry-run
						// delete is only distinguishable by its requestObject.
						Desc: "dry-run delete is logged like a real delete; dryRun is visible only in the DeleteOptions body", Requirement: ReqEdge,
						Match: audit.Match{Verb: "delete", Resource: "pods", Namespace: ns, Name: podPlain},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"dryRun":["All"]`},
					},
					{
						Desc: "dry-run secret create stays at Metadata without body", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "create", Resource: "secrets", Namespace: ns, Name: "dryrun-secret"},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
				}
			},
		},
		{
			Name: "pagination-and-selectors",
			Act: func(ctx context.Context, env *audit.Env) error {
				pods := env.Client.CoreV1().Pods(env.Namespace)
				first, err := pods.List(ctx, metav1.ListOptions{Limit: 1})
				if err != nil {
					return err
				}
				if first.Continue != "" {
					if _, err := pods.List(ctx, metav1.ListOptions{Limit: 1, Continue: first.Continue}); err != nil {
						return err
					}
				}
				if _, err := pods.List(ctx, metav1.ListOptions{LabelSelector: "audit-test=plain"}); err != nil {
					return err
				}
				if _, err := pods.List(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"}); err != nil {
					return err
				}
				_, err = env.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 5})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "each page of a chunked list is a separate Metadata event", Requirement: ReqHumans, Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, URIContains: "limit=1"}, Level: "Metadata", MinEvents: 2},
					{Desc: "continue token appears in the URI of the second page", Requirement: ReqEdge, Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, URIContains: "continue="}, Level: "Metadata"},
					{Desc: "label selector list is logged with the selector in the URI", Requirement: ReqHumans, Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, URIContains: "labelSelector=audit-test"}, Level: "Metadata"},
					{Desc: "field selector list is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, URIContains: "fieldSelector=status.phase"}, Level: "Metadata"},
					{Desc: "cluster-wide pod list by a human is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "list", Resource: "pods", URIPrefix: "/api/v1/pods", URIContains: "limit=5"}, Level: "Metadata"},
				}
			},
		},
		{
			Name: "logs-follow-previous-tail",
			Act: func(ctx context.Context, env *audit.Env) error {
				pods := env.Client.CoreV1().Pods(env.Namespace)
				fctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				stream, err := pods.GetLogs(podPlain, &corev1.PodLogOptions{Follow: true}).Stream(fctx)
				if err != nil {
					return fmt.Errorf("follow logs: %w", err)
				}
				_, _ = io.Copy(io.Discard, stream)
				stream.Close()
				// No previous container instance: the apiserver answers 400.
				_, _ = pods.GetLogs(podPlain, &corev1.PodLogOptions{Previous: true}).DoRaw(ctx)
				_, err = pods.GetLogs(podPlain, &corev1.PodLogOptions{TailLines: int64p(5)}).DoRaw(ctx)
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "kubectl logs -f is logged at Metadata with both stages (long-running)", Requirement: ReqHumans,
						Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "log", Namespace: ns, Name: podPlain, URIContains: "follow=true"},
						Level: "Metadata", Stages: []string{"ResponseStarted", "ResponseComplete"},
					},
					{
						Desc: "failed log request (previous=true, 400) is logged", Requirement: ReqEdge,
						Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "log", Namespace: ns, Name: podPlain, URIContains: "previous=true"},
						Level: "Metadata", Code: 400,
					},
					{
						Desc: "kubectl logs --tail is logged", Requirement: ReqHumans,
						Match: audit.Match{Verb: "get", Resource: "pods", Subresource: "log", Namespace: ns, Name: podPlain, URIContains: "tailLines=5"},
						Level: "Metadata",
					},
				}
			},
		},
		{
			// Status and binding subresources written by a human instead of
			// the kubelet / scheduler: the drops are user-scoped, so these
			// fall through to Request with body.
			Name: "pod-status-and-manual-binding",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				pods := env.Client.CoreV1().Pods(ns)
				patch := fmt.Appendf(nil, `{"status":{"conditions":[{"type":%q,"status":"True"}]}}`, env.Label("Probe"))
				if _, err := pods.Patch(ctx, podPlain, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status"); err != nil {
					return fmt.Errorf("patch pods/status: %w", err)
				}
				plain, err := pods.Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				env.WorkerNode = plain.Spec.NodeName
				p := sleepPod(podManualBind, env.Image, nil)
				p.Spec.SchedulerName = "audit-test-none" // no scheduler picks it up
				if _, err := pods.Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return err
				}
				return pods.Bind(ctx, &corev1.Binding{
					ObjectMeta: metav1.ObjectMeta{Name: podManualBind, Namespace: ns},
					Target:     corev1.ObjectReference{Kind: "Node", Name: plain.Spec.NodeName},
				}, metav1.CreateOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "pods/status written by a human is logged at Request with body", Requirement: ReqHumans,
						Match: audit.Match{Verb: "patch", Resource: "pods", Subresource: "status", Namespace: ns, Name: podPlain},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{env.Label("Probe")},
					},
					{
						Desc: "manual pod binding by a human (scheduler bypass) is logged at Request with the target node", Requirement: ReqHumans,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "binding", Namespace: ns, Name: podManualBind},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{env.WorkerNode},
					},
					{
						Desc: "the scheduler never bound the manually bound pod", Requirement: ReqEdge,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "binding", Namespace: ns, Name: podManualBind, User: "system:kube-scheduler", AnyUA: true},
						Level: "None",
					},
				}
			},
		},
		{
			// kubectl auth whoami / can-i --list, LocalSubjectAccessReview and
			// a TokenReview by an admin (its body carries the reviewed token).
			Name: "identity-introspection",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				if _, err := env.Client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("selfsubjectreview: %w", err)
				}
				if _, err := env.Client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authzv1.SelfSubjectRulesReview{
					Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: ns},
				}, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("selfsubjectrulesreview: %w", err)
				}
				if _, err := env.Client.AuthorizationV1().LocalSubjectAccessReviews(ns).Create(ctx, &authzv1.LocalSubjectAccessReview{
					ObjectMeta: metav1.ObjectMeta{Namespace: ns},
					Spec: authzv1.SubjectAccessReviewSpec{
						User:               saUser(ns, saWorker),
						ResourceAttributes: &authzv1.ResourceAttributes{Namespace: ns, Verb: "delete", Resource: "pods"},
					},
				}, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("localsubjectaccessreview: %w", err)
				}
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				_, err = env.Client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
					Spec: authnv1.TokenReviewSpec{Token: tok},
				}, metav1.CreateOptions{})
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{Desc: "kubectl auth whoami (SelfSubjectReview) is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Group: "authentication.k8s.io", Resource: "selfsubjectreviews"}, Level: "Request"},
					{Desc: "kubectl auth can-i --list (SelfSubjectRulesReview) is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Group: "authorization.k8s.io", Resource: "selfsubjectrulesreviews"}, Level: "Request", RequestBody: audit.Required},
					{Desc: "LocalSubjectAccessReview by a human is logged with body", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Group: "authorization.k8s.io", Resource: "localsubjectaccessreviews", Namespace: env.Namespace}, Level: "Request", RequestBody: audit.Required},
					{
						Desc: "TokenReview by a human is Metadata: the reviewed token is not in the log", Requirement: ReqHygiene,
						Match: audit.Match{Verb: "create", Group: "authentication.k8s.io", Resource: "tokenreviews"},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
				}
			},
		},
		{
			// Leader-election leases: heartbeats (get/update) by any service
			// account are dropped; create and delete stay logged; humans
			// touching leases are always logged.
			Name: "leases-by-humans-and-workload-sa",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				leases := env.Client.CoordinationV1().Leases(ns)
				holder := "audit-human"
				l, err := leases.Create(ctx, &coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{Name: "human-lease"},
					Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: int32p(15)},
				}, metav1.CreateOptions{})
				if err != nil {
					return err
				}
				if _, err := leases.Get(ctx, "human-lease", metav1.GetOptions{}); err != nil {
					return err
				}
				holder2 := "audit-human-2"
				l.Spec.HolderIdentity = &holder2
				if _, err := leases.Update(ctx, l, metav1.UpdateOptions{}); err != nil {
					return err
				}
				rb := env.Client.RbacV1()
				if _, err := rb.Roles(ns).Create(ctx, &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-lease-user"},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create", "update", "delete"}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := rb.RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-lease-user"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saWorker, Namespace: ns}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "audit-lease-user"},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, saWorker)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				saLeases := cl.CoordinationV1().Leases(ns)
				saHolder := "audit-worker"
				var sl *coordinationv1.Lease
				if err := untilAllowed(ctx, 15*time.Second, func() error {
					var err error
					sl, err = saLeases.Create(ctx, &coordinationv1.Lease{
						ObjectMeta: metav1.ObjectMeta{Name: "sa-lease"},
						Spec:       coordinationv1.LeaseSpec{HolderIdentity: &saHolder, LeaseDurationSeconds: int32p(15)},
					}, metav1.CreateOptions{})
					return err
				}); err != nil {
					return fmt.Errorf("sa create lease: %w", err)
				}
				if _, err := saLeases.Get(ctx, "sa-lease", metav1.GetOptions{}); err != nil {
					return err
				}
				now := metav1.NowMicro()
				sl.Spec.RenewTime = &now
				if _, err := saLeases.Update(ctx, sl, metav1.UpdateOptions{}); err != nil {
					return fmt.Errorf("sa renew lease: %w", err)
				}
				if err := saLeases.Delete(ctx, "sa-lease", metav1.DeleteOptions{}); err != nil {
					return err
				}
				return leases.Delete(ctx, "human-lease", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				g := "coordination.k8s.io"
				worker := saUser(ns, saWorker)
				return []audit.Expect{
					{Desc: "lease create by a human is logged with body", Requirement: ReqHumans, Match: audit.Match{Verb: "create", Group: g, Resource: "leases", Namespace: ns, Name: "human-lease"}, Level: "Request", RequestBody: audit.Required},
					{Desc: "lease get by a human is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "get", Group: g, Resource: "leases", Namespace: ns, Name: "human-lease"}, Level: "Metadata"},
					{Desc: "lease update by a human is logged with body", Requirement: ReqHumans, Match: audit.Match{Verb: "update", Group: g, Resource: "leases", Namespace: ns, Name: "human-lease"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"audit-human-2"}},
					{Desc: "lease delete by a human is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "delete", Group: g, Resource: "leases", Namespace: ns, Name: "human-lease"}, Level: "Request"},
					{Desc: "lease create by a unprivileged SA is logged with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: g, Resource: "leases", Namespace: ns, Name: "sa-lease", User: worker}, Level: "Request", RequestBody: audit.Required},
					{
						Desc: "lease heartbeats (get/update) by a unprivileged SA are dropped", Requirement: ReqNoise,
						Match: audit.Match{Verbs: []string{"get", "update", "patch"}, Group: g, Resource: "leases", Namespace: ns, Name: "sa-lease", User: worker},
						Level: "None",
					},
					{Desc: "lease delete by a unprivileged SA is logged", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: g, Resource: "leases", Namespace: ns, Name: "sa-lease", User: worker}, Level: "Request"},
				}
			},
		},
		{
			// A CRD with a status subresource, and the custom resources behind
			// it: their API group is unknown to the policy, so writes fall
			// through to the operator rule (Request) and reads to the catch-all.
			Name: "custom-resources",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				if _, err := env.Dynamic.Resource(crdGVR).Create(ctx, edgeCRD(env), metav1.CreateOptions{}); err != nil {
					return err
				}
				deadline := time.Now().Add(30 * time.Second)
				for {
					crd, err := env.Dynamic.Resource(crdGVR).Get(ctx, edgeCRDName(env), metav1.GetOptions{})
					if err != nil {
						return err
					}
					conds, _, _ := unstructured.NestedSlice(crd.Object, "status", "conditions")
					established := false
					for _, c := range conds {
						m, _ := c.(map[string]any)
						if m["type"] == "Established" && m["status"] == "True" {
							established = true
						}
					}
					if established || time.Now().After(deadline) {
						break
					}
					time.Sleep(time.Second)
				}
				marker := "audit-cr-" + env.RunID
				crs := env.Dynamic.Resource(edgeGVR(env)).Namespace(ns)
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": env.Domain + "/v1", "kind": "EdgeTest",
					"metadata": map[string]any{"name": "edge-1"},
					"spec":     map[string]any{"marker": marker},
				}}
				// The new resource handler may take a moment to be served.
				deadline = time.Now().Add(20 * time.Second)
				for {
					_, err := crs.Create(ctx, obj, metav1.CreateOptions{})
					if err == nil || !apierrors.IsNotFound(err) || time.Now().After(deadline) {
						if err != nil {
							return fmt.Errorf("create custom resource: %w", err)
						}
						break
					}
					time.Sleep(time.Second)
				}
				if _, err := crs.Patch(ctx, "edge-1", types.MergePatchType, []byte(`{"spec":{"patched":true}}`), metav1.PatchOptions{}); err != nil {
					return err
				}
				cur, err := crs.Get(ctx, "edge-1", metav1.GetOptions{})
				if err != nil {
					return err
				}
				_ = unstructured.SetNestedField(cur.Object, "Audited", "status", "phase")
				if _, err := crs.UpdateStatus(ctx, cur, metav1.UpdateOptions{}); err != nil {
					return fmt.Errorf("update status: %w", err)
				}
				if err := crs.Delete(ctx, "edge-1", metav1.DeleteOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				dc, err := dynamicWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := dc.Resource(edgeGVR(env)).Namespace(ns).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA listing custom resources, got %v", err)
				}
				return env.Dynamic.Resource(crdGVR).Delete(ctx, edgeCRDName(env), metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				marker := "audit-cr-" + env.RunID
				return []audit.Expect{
					{Desc: "CRD (with status subresource) create with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Name: edgeCRDName(env)}, Level: "Request", RequestBody: audit.Required},
					{Desc: "CRD delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Name: edgeCRDName(env)}, Level: "Request"},
					{Desc: "custom resource create (unknown API group) with body", Requirement: ReqResources, Match: audit.Match{Verb: "create", Group: env.Domain, Resource: edgeCRDResource, Subresource: "-", Namespace: ns, Name: "edge-1"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{marker}},
					{Desc: "custom resource patch with body", Requirement: ReqResources, Match: audit.Match{Verb: "patch", Group: env.Domain, Resource: edgeCRDResource, Namespace: ns, Name: "edge-1"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"patched":true`}},
					{Desc: "custom resource status written by a human is logged with body (not dropped)", Requirement: ReqHumans, Match: audit.Match{Verb: "update", Group: env.Domain, Resource: edgeCRDResource, Subresource: "status", Namespace: ns, Name: "edge-1"}, Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"Audited"}},
					{Desc: "custom resource delete", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: env.Domain, Resource: edgeCRDResource, Namespace: ns, Name: "edge-1"}, Level: "Request"},
					{Desc: "custom resource get by a human is logged", Requirement: ReqHumans, Match: audit.Match{Verb: "get", Group: env.Domain, Resource: edgeCRDResource, Namespace: ns, Name: "edge-1"}, Level: "Metadata"},
					{Desc: "denied custom resource list by a unprivileged SA is logged", Requirement: ReqAuthFail, Match: audit.Match{Verb: "list", Group: env.Domain, Resource: edgeCRDResource, Namespace: ns, User: saUser(ns, saRestricted)}, Level: "Metadata", Code: 403, Annotations: forbidAnn},
				}
			},
		},

		// ==================================================================
		// Error paths
		// ==================================================================
		{
			Name: "error-responses",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				pods := env.Client.CoreV1().Pods(ns)
				rc := env.Client.CoreV1().RESTClient()
				// 422: a pod without containers
				if _, err := pods.Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "invalid"}}, metav1.CreateOptions{}); !apierrors.IsInvalid(err) {
					return fmt.Errorf("expected 422, got %v", err)
				}
				// 400: a body that is not JSON
				_, err := rc.Post().Namespace(ns).Resource("pods").SetHeader("Content-Type", "application/json").
					Body([]byte(`{"apiVersion":"v1","kind":"Pod",`)).DoRaw(ctx)
				if !apierrors.IsBadRequest(err) {
					return fmt.Errorf("expected 400, got %v", err)
				}
				// 409: create an existing pod
				if _, err := pods.Create(ctx, sleepPod(podPlain, env.Image, nil), metav1.CreateOptions{}); !apierrors.IsAlreadyExists(err) {
					return fmt.Errorf("expected 409 AlreadyExists, got %v", err)
				}
				// 409: update with a stale resourceVersion
				p, err := pods.Get(ctx, podPlain, metav1.GetOptions{})
				if err != nil {
					return err
				}
				p.ResourceVersion = "1"
				p.Labels["audit-test-conflict"] = env.RunID
				if _, err := pods.Update(ctx, p, metav1.UpdateOptions{}); !apierrors.IsConflict(err) {
					return fmt.Errorf("expected 409 Conflict, got %v", err)
				}
				// 404: delete and get objects that do not exist
				ghost := "ghost-" + env.RunID
				if err := pods.Delete(ctx, ghost, metav1.DeleteOptions{}); !apierrors.IsNotFound(err) {
					return fmt.Errorf("expected 404, got %v", err)
				}
				if err := env.Client.CoreV1().Secrets(ns).Delete(ctx, ghost, metav1.DeleteOptions{}); !apierrors.IsNotFound(err) {
					return fmt.Errorf("expected 404, got %v", err)
				}
				if _, err := env.Client.CoreV1().Secrets(ns).Get(ctx, ghost, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
					return fmt.Errorf("expected 404, got %v", err)
				}
				// 405: PUT on a collection
				if _, err := rc.Put().Namespace(ns).Resource("pods").Body([]byte(`{}`)).DoRaw(ctx); err == nil {
					return fmt.Errorf("PUT on a collection succeeded")
				}
				// 415: unsupported media type
				if _, err := rc.Post().Namespace(ns).Resource("configmaps").SetHeader("Content-Type", "text/plain").Body([]byte(`hello`)).DoRaw(ctx); err == nil {
					return fmt.Errorf("text/plain POST succeeded")
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				ghost := "ghost-" + env.RunID
				return []audit.Expect{
					{Desc: "rejected pod (422 validation) is logged with the invalid body", Requirement: ReqEdge, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: "invalid"}, Level: "Request", Code: 422, RequestBody: audit.Required},
					{Desc: "undecodable body (400) is logged", Requirement: ReqEdge, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, ResponseCode: 400}, Level: "Request", Code: 400},
					{Desc: "duplicate create (409 AlreadyExists) is logged with body", Requirement: ReqEdge, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: podPlain, ResponseCode: 409}, Level: "Request", Code: 409, RequestBody: audit.Required},
					{Desc: "stale update (409 Conflict) is logged with body", Requirement: ReqEdge, Match: audit.Match{Verb: "update", Resource: "pods", Subresource: "-", Namespace: ns, Name: podPlain, ResponseCode: 409}, Level: "Request", Code: 409, RequestBody: audit.Required, RequestBodyContains: []string{"audit-test-conflict"}},
					{Desc: "delete of a nonexistent pod (404) is logged", Requirement: ReqEdge, Match: audit.Match{Verb: "delete", Resource: "pods", Namespace: ns, Name: ghost}, Level: "Request", Code: 404},
					{Desc: "delete of a nonexistent secret (404) is logged at Metadata", Requirement: ReqSecrets, Match: audit.Match{Verb: "delete", Resource: "secrets", Namespace: ns, Name: ghost}, Level: "Metadata", Code: 404, RequestBody: audit.Forbidden},
					{Desc: "get of a nonexistent secret (404) is logged at Metadata", Requirement: ReqSecrets, Match: audit.Match{Verb: "get", Resource: "secrets", Namespace: ns, Name: ghost}, Level: "Metadata", Code: 404},
					{Desc: "unsupported method on a collection (PUT, 405) is logged", Requirement: ReqEdge, Match: audit.Match{Verb: "update", Resource: "pods", URI: "/api/v1/namespaces/" + ns + "/pods"}, Level: "Request", Code: 405},
					{Desc: "unsupported media type (415) is logged", Requirement: ReqEdge, Match: audit.Match{Verb: "create", Resource: "configmaps", Namespace: ns, ResponseCode: 415}, Level: "Metadata", Code: 415},
				}
			},
		},
		{
			// Reconnaissance: paths a scanner or a curious user would try.
			// Unknown resources are still resource requests (logged); unknown
			// non-resource paths hit the catch-all (logged); real discovery
			// paths are dropped.
			Name: "api-probing",
			Act: func(ctx context.Context, env *audit.Env) error {
				for _, p := range []string{
					"/api/v1/nonexistentresources",
					"/apis/nonexistent.example.com/v1/things",
					"/apis/apps/v1",
					"/foo/bar",
					"/API/v1",
					"/openapi/v3",
					"/debug/pprof/",
					"/logs/",
					"/.well-known/openid-configuration",
					"/openid/v1/jwks",
					"/apis/metrics.k8s.io/v1beta1/nodes",
				} {
					_ = rawGet(ctx, env.Client, p)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				nr := func(uri string) audit.Match { return audit.Match{NonResource: true, URIPrefix: uri} }
				return []audit.Expect{
					{Desc: "unknown core resource (404) is logged as a resource request", Requirement: ReqEdge, Match: audit.Match{Verb: "list", Group: "core", Resource: "nonexistentresources"}, Level: "Metadata", Code: 404},
					{Desc: "unknown API group (404) is logged as a resource request", Requirement: ReqEdge, Match: audit.Match{Verb: "list", Group: "nonexistent.example.com", Resource: "things"}, Level: "Metadata", Code: 404},
					{Desc: "group-version discovery (/apis/apps/v1) is dropped", Requirement: ReqNoise, Match: audit.Match{NonResource: true, URI: "/apis/apps/v1"}, Level: "None"},
					{Desc: "unknown non-resource path (/foo/bar, 404) is logged", Requirement: ReqEdge, Match: nr("/foo/bar"), Level: "Metadata", Code: 404},
					{Desc: "wrong-case API prefix (/API/v1) is not discovery and is logged", Requirement: ReqEdge, Match: nr("/API/v1"), Level: "Metadata", Code: 404},
					{Desc: "/openapi/v3 discovery is dropped", Requirement: ReqNoise, Match: nr("/openapi/v3"), Level: "None"},
					{Desc: "/debug/pprof access is logged", Requirement: ReqHumans, Match: nr("/debug/pprof"), Level: "Metadata"},
					{Desc: "/logs access is logged", Requirement: ReqHumans, Match: nr("/logs"), Level: "Metadata"},
					{Desc: "OIDC discovery document read is logged", Requirement: ReqHumans, Match: nr("/.well-known/openid-configuration"), Level: "Metadata"},
					{Desc: "service account JWKS read is logged", Requirement: ReqHumans, Match: nr("/openid/v1/jwks"), Level: "Metadata"},
					{Desc: "metrics.k8s.io read (kubectl top) is logged whether or not metrics-server exists", Requirement: ReqHumans, Match: audit.Match{Verb: "list", Group: "metrics.k8s.io", Resource: "nodes"}, Level: "Metadata"},
				}
			},
		},

		// ==================================================================
		// Anonymous and authentication oddities
		// ==================================================================
		{
			Name: "anonymous-extended",
			Act: func(ctx context.Context, env *audit.Env) error {
				anonCfg := env.AnonymousConfig()
				cl, err := kubernetes.NewForConfig(anonCfg)
				if err != nil {
					return err
				}
				rc := cl.CoreV1().RESTClient()
				for _, p := range []string{"/metrics", "/openapi/v2", "/apis", "/.well-known/openid-configuration", "/index.html"} {
					_ = rawGet(ctx, cl, p)
				}
				_, _ = rc.Verb("HEAD").AbsPath("/").DoRaw(ctx)
				_, _ = rc.Verb("OPTIONS").AbsPath("/").DoRaw(ctx)
				if _, err := cl.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: env.Name("anon")}}, metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for anonymous namespace create, got %v", err)
				}
				req := rc.Post().Resource("pods").Namespace(env.Namespace).Name("ghost").SubResource("exec").
					VersionedParams(&corev1.PodExecOptions{Command: []string{"sh"}, Stdin: true, Stdout: true, TTY: true}, scheme.ParameterCodec)
				ex, err := remotecommand.NewSPDYExecutor(anonCfg, "POST", req.URL())
				if err != nil {
					return err
				}
				_ = ex.StreamWithContext(ctx, remotecommand.StreamOptions{})
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				anon := func(uri string) audit.Match {
					return audit.Match{User: "system:anonymous", NonResource: true, URIPrefix: uri}
				}
				return []audit.Expect{
					{Desc: "anonymous /metrics is logged (403)", Requirement: ReqAnonymous, Match: anon("/metrics"), Level: "Metadata", Code: 403},
					{Desc: "anonymous /openapi is logged (the discovery drop is for authenticated users only)", Requirement: ReqAnonymous, Match: anon("/openapi"), Level: "Metadata"},
					{Desc: "anonymous OIDC discovery read is logged", Requirement: ReqAnonymous, Match: anon("/.well-known"), Level: "Metadata"},
					{Desc: "anonymous probe of an unknown path is logged", Requirement: ReqAnonymous, Match: anon("/index.html"), Level: "Metadata"},
					{
						Desc: "anonymous HEAD / is logged: the load-balancer probe drop covers only GET (verb head)", Requirement: ReqEdge,
						Match: audit.Match{User: "system:anonymous", NonResource: true, URI: "/", Verb: "head"}, Level: "Metadata",
					},
					{
						Desc: "anonymous OPTIONS / is logged (verb options)", Requirement: ReqEdge,
						Match: audit.Match{User: "system:anonymous", NonResource: true, URI: "/", Verb: "options"}, Level: "Metadata",
					},
					{
						Desc: "anonymous write attempt (namespace create) is logged with 403 and no body", Requirement: ReqAnonymous,
						Match: audit.Match{Verb: "create", Resource: "namespaces", User: "system:anonymous"},
						Level: "Request", Code: 403, Annotations: forbidAnn, RequestBody: audit.Forbidden,
					},
					{
						Desc: "anonymous exec attempt is logged with 403", Requirement: ReqAnonymous,
						Match: audit.Match{Resource: "pods", Subresource: "exec", Namespace: env.Namespace, Name: "ghost", User: "system:anonymous"},
						Level: "Metadata", Code: 403, Annotations: forbidAnn,
					},
				}
			},
		},
		{
			Name: "authn-edge-cases",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				// 1. A valid token whose service account was deleted afterwards.
				if _, err := env.Client.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "ephemeral"}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, "ephemeral")
				if err != nil {
					return err
				}
				if err := env.Client.CoreV1().ServiceAccounts(ns).Delete(ctx, "ephemeral", metav1.DeleteOptions{}); err != nil {
					return err
				}
				gone, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := gone.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{}); !apierrors.IsUnauthorized(err) {
					return fmt.Errorf("expected 401 for the token of a deleted SA, got %v", err)
				}
				// 2. Credentials the apiserver does not understand fall back to anonymous.
				anon, err := kubernetes.NewForConfig(env.AnonymousConfig())
				if err != nil {
					return err
				}
				rc := anon.CoreV1().RESTClient()
				basic := base64.StdEncoding.EncodeToString([]byte("audit:hunter2"))
				_, err = rc.Get().Namespace(ns).Resource("configmaps").SetHeader("Authorization", "Basic "+basic).DoRaw(ctx)
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 (anonymous) for basic auth, got %v", err)
				}
				_, err = rc.Get().Namespace(ns).Resource("serviceaccounts").SetHeader("Authorization", "Bearer ").DoRaw(ctx)
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 (anonymous) for an empty bearer token, got %v", err)
				}
				// 3. Anonymous client sending impersonation headers.
				_, err = rc.Get().Resource("nodes").SetHeader("Impersonate-User", "system:admin").DoRaw(ctx)
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for anonymous impersonation, got %v", err)
				}
				// 4. Invalid token on a watch.
				bad, err := clientWithToken(env, "audit-invalid-watch-token-"+env.RunID)
				if err != nil {
					return err
				}
				if _, err := bad.CoreV1().Pods(ns).Watch(ctx, metav1.ListOptions{TimeoutSeconds: int64p(2)}); !apierrors.IsUnauthorized(err) {
					return fmt.Errorf("expected 401 for a watch with an invalid token, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "token of a deleted service account is rejected (401) and logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "list", Resource: "serviceaccounts", Namespace: ns, ResponseCode: 401},
						Level: "Metadata", Code: 401, UsernameEmpty: true, Stages: []string{"ResponseStarted"},
					},
					{
						Desc: "basic auth is treated as anonymous (403, not 401) and logged", Requirement: ReqEdge,
						Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: ns, User: "system:anonymous"},
						Level: "Metadata", Code: 403,
					},
					{
						Desc: "empty bearer token is treated as anonymous and logged", Requirement: ReqEdge,
						Match: audit.Match{Verb: "list", Resource: "serviceaccounts", Namespace: ns, User: "system:anonymous"},
						Level: "Metadata", Code: 403,
					},
					{
						Desc: "impersonation attempt by an anonymous client is logged without impersonatedUser", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "nodes", User: "system:anonymous"},
						Level: "Metadata", Code: 403, NoImpersonation: true,
					},
					{
						Desc: "invalid bearer token on a watch (401) is logged", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "watch", Resource: "pods", Namespace: ns, ResponseCode: 401},
						Level: "Metadata", Code: 401, UsernameEmpty: true,
						Gap: "401s are emitted at stage ResponseStarted; the watch rule sets omitStages: [ResponseStarted], so failed authentication on any watch is invisible",
					},
				}
			},
		},
		{
			Name: "impersonation-edge-cases",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				// a) uid, groups and extra
				withUID, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{
						UserName: "audit-uid-user-" + env.RunID, UID: "audit-uid-" + env.RunID,
						Groups: []string{"audit-uid-group"},
						Extra:  map[string][]string{env.Label("reason"): {"edge"}},
					}
				}))
				if err != nil {
					return err
				}
				if _, err := withUID.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{}); ignoreForbidden(err) != nil {
					return err
				}
				// b) impersonating system:anonymous
				asAnon, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{UserName: "system:anonymous"}
				}))
				if err != nil {
					return err
				}
				if _, err := asAnon.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{}); ignoreForbidden(err) != nil {
					return err
				}
				// c) a restricted SA trying to impersonate someone
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				climb, err := clientAs(env, tok, "audit-victim-"+env.RunID, nil)
				if err != nil {
					return err
				}
				if _, err := climb.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA impersonating, got %v", err)
				}
				// d) malformed: Impersonate-Group without Impersonate-User
				_, err = env.Client.CoreV1().RESTClient().Get().Namespace(ns).Resource("pods").
					Param("labelSelector", "audit-malformed-impersonation=1").
					SetHeader("Impersonate-Group", "audit-orphan-group").DoRaw(ctx)
				if err == nil {
					return fmt.Errorf("group-only impersonation succeeded")
				}
				// e) impersonating a managed SA and writing
				asSA, err := kubernetes.NewForConfig(env.ConfigFor(func(c *rest.Config) {
					c.Impersonate = rest.ImpersonationConfig{UserName: saUser("kube-system", "default")}
				}))
				if err != nil {
					return err
				}
				if _, err := asSA.CoreV1().Pods(ns).Create(ctx, sleepPod("imp-pod", env.Image, nil), metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for kube-system:default creating a pod, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "impersonated uid and groups are recorded", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: ns, ImpersonatedUser: "audit-uid-user-" + env.RunID},
						Level: "Metadata", ImpersonatedUID: "audit-uid-" + env.RunID, ImpersonatedGroups: []string{"audit-uid-group", "system:authenticated"},
					},
					{
						Desc: "impersonating system:anonymous is attributed to the real admin", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "serviceaccounts", Namespace: ns, ImpersonatedUser: "system:anonymous"},
						Level: "Metadata", Impersonated: "system:anonymous", ImpersonatedGroups: []string{"system:unauthenticated"},
					},
					{
						Desc: "denied impersonation by a unprivileged SA is logged (403, no impersonatedUser, no decision annotation)", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "configmaps", Namespace: ns, User: saUser(ns, saRestricted)},
						Level: "Metadata", Code: 403, NoImpersonation: true, AnnotationsAbsent: []string{decisionKey},
					},
					{
						Desc: "malformed impersonation headers (group without user) are logged", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, URIContains: "audit-malformed-impersonation"},
						Level: "Metadata", NoImpersonation: true,
					},
					{
						Desc: "write while impersonating a managed SA is logged at Request with the impersonated identity", Requirement: ReqImpersonate,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, ImpersonatedUser: saUser("kube-system", "default")},
						Level: "Request", Code: 403, Impersonated: saUser("kube-system", "default"), Annotations: forbidAnn, RequestBody: audit.Forbidden,
					},
				}
			},
		},

		// ==================================================================
		// RBAC and credentials
		// ==================================================================
		{
			// RBAC escalation prevention rejects a Role/RoleBinding in the
			// registry, after authorization allowed the request: the audit
			// event has code 403, decision "allow" and the attempted rules in
			// the body.
			Name: "rbac-escalation-prevention",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				rb := env.Client.RbacV1()
				if _, err := rb.Roles(ns).Create(ctx, &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-rbac-editor"},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles", "rolebindings"}, Verbs: []string{"create", "delete"}}},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if _, err := rb.RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-rbac-editor"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saWorker, Namespace: ns}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "audit-rbac-editor"},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, saWorker)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				// Within its own permissions: allowed.
				if err := untilAllowed(ctx, 15*time.Second, func() error {
					_, err := cl.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "within-bounds"},
						Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
					}, metav1.CreateOptions{})
					return err
				}); err != nil {
					return fmt.Errorf("worker creating a role within its permissions: %w", err)
				}
				if err := cl.RbacV1().Roles(ns).Delete(ctx, "within-bounds", metav1.DeleteOptions{}); err != nil {
					return err
				}
				// Escalation: granting what it does not hold.
				_, err = cl.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "escalated"},
					Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}},
				}, metav1.CreateOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 (escalation) for role create, got %v", err)
				}
				// Binding a role it may not bind.
				_, err = cl.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "bind-cluster-admin"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saWorker, Namespace: ns}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
				}, metav1.CreateOptions{})
				if !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 (bind) for rolebinding create, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				g := "rbac.authorization.k8s.io"
				worker := saUser(ns, saWorker)
				return []audit.Expect{
					{
						Desc: "role create within own permissions by a unprivileged SA is logged with body", Requirement: ReqRBAC,
						Match: audit.Match{Verb: "create", Group: g, Resource: "roles", Namespace: ns, Name: "within-bounds", User: worker},
						Level: "Request", Code: 201, RequestBody: audit.Required,
					},
					{Desc: "role delete by a unprivileged SA is logged", Requirement: ReqRBAC, Match: audit.Match{Verb: "delete", Group: g, Resource: "roles", Namespace: ns, Name: "within-bounds", User: worker}, Level: "Request"},
					{
						Desc: "RBAC escalation attempt: 403 with decision=allow and the attempted rules in the body", Requirement: ReqIncident,
						Match: audit.Match{Verb: "create", Group: g, Resource: "roles", Namespace: ns, Name: "escalated", User: worker},
						Level: "Request", Code: 403, Annotations: allowAnn, RequestBody: audit.Required, RequestBodyContains: []string{`"secrets"`},
					},
					{
						Desc: "RBAC bind attempt to cluster-admin: 403 with decision=allow and the binding in the body", Requirement: ReqIncident,
						Match: audit.Match{Verb: "create", Group: g, Resource: "rolebindings", Namespace: ns, Name: "bind-cluster-admin", User: worker},
						Level: "Request", Code: 403, Annotations: allowAnn, RequestBody: audit.Required, RequestBodyContains: []string{"cluster-admin"},
					},
				}
			},
		},
		{
			// Lateral movement through credentials: a restricted SA requesting
			// a token for another account, and the legacy long-lived token
			// secret that the token-controller fills in.
			Name: "token-lateral-movement",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().ServiceAccounts(ns).CreateToken(ctx, saWorker, &authnv1.TokenRequest{}, metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA minting a worker token, got %v", err)
				}
				secrets := env.Client.CoreV1().Secrets(ns)
				if _, err := secrets.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "legacy-token", Annotations: map[string]string{corev1.ServiceAccountNameKey: saRestricted}},
					Type:       corev1.SecretTypeServiceAccountToken,
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				deadline := time.Now().Add(20 * time.Second)
				for {
					s, err := secrets.Get(ctx, "legacy-token", metav1.GetOptions{})
					if err != nil {
						return err
					}
					if len(s.Data[corev1.ServiceAccountTokenKey]) > 0 {
						env.AddMarker("legacy service account token", string(s.Data[corev1.ServiceAccountTokenKey]))
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("token-controller did not populate the legacy token secret")
					}
					time.Sleep(time.Second)
				}
				return secrets.Delete(ctx, "legacy-token", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "denied TokenRequest for another account is logged at Metadata", Requirement: ReqIncident,
						Match: audit.Match{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: ns, Name: saWorker, User: saUser(ns, saRestricted)},
						Level: "Metadata", Code: 403, Annotations: forbidAnn, RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
					{
						// The token controller runs inside kube-controller-manager
						// with its main identity, not a per-controller SA.
						Desc: "token-controller filling a legacy token secret is Metadata without the token", Requirement: ReqSecrets,
						Match: audit.Match{Verbs: []string{"update", "patch"}, Resource: "secrets", Namespace: ns, Name: "legacy-token", UserPrefix: "system:kube-", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
					{
						Desc: "token-controller reading the legacy token secret is logged (secrets rule precedes the controller read drop)", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "get", Resource: "secrets", Namespace: ns, Name: "legacy-token", UserPrefix: "system:kube-", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
					{
						Desc: "legacy token secret create by a human is logged at Metadata", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "create", Resource: "secrets", Namespace: ns, Name: "legacy-token"},
						Level: "Metadata", RequestBody: audit.Forbidden,
					},
				}
			},
		},
		{
			// A pod consuming a secret: the kubelet fetches the secret and
			// mints a token for the pod's service account. Secret access is
			// logged whoever reads it; the token request stays body-less.
			Name: "pod-with-secret-volume",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				value := "MOUNTED-SECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("mounted secret value", value)
				env.AddMarker("mounted secret value (base64)", base64.StdEncoding.EncodeToString([]byte(value)))
				if _, err := env.Client.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: secretMounted}, StringData: map[string]string{"password": value},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				p := sleepPod(podSecretConsumer, env.Image, nil)
				p.Spec.Volumes = []corev1.Volume{{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretMounted}}}}
				p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "s", MountPath: "/secret"}}
				p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "PASSWORD", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretMounted}, Key: "password"},
				}}}
				if _, err := env.Client.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return err
				}
				_, err := waitPodRunning(ctx, env.Client, ns, podSecretConsumer, 3*time.Minute)
				return err
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "pod referencing a secret is logged with the reference but the value never appears", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: ns, Name: podSecretConsumer},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{`"secretName":"` + secretMounted + `"`, "secretKeyRef"},
					},
					{
						Desc: "kubelet fetching the mounted secret is logged at Metadata (secrets rule precedes the node-read drop)", Requirement: ReqSecrets,
						Match: audit.Match{Verbs: []string{"get", "list"}, Resource: "secrets", Namespace: ns, UserGroup: "system:nodes", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
					{
						Desc: "kubelet secret watches are Metadata, ResponseComplete only", Requirement: ReqSecrets,
						Match: audit.Match{Verb: "watch", Resource: "secrets", Namespace: ns, UserGroup: "system:nodes", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, Stages: []string{"ResponseComplete"}, AllowNone: true,
					},
					{
						Desc: "kubelet TokenRequest for a pod's service account is Metadata without body", Requirement: ReqTokens,
						Match: audit.Match{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Namespace: ns, UserGroup: "system:nodes", AnyUA: true},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden,
					},
				}
			},
		},

		// ==================================================================
		// Bulk operations and cluster-level changes
		// ==================================================================
		{
			// kubectl delete all --all / delete -l: deletecollection per
			// resource type; a denied bulk delete by a unprivileged SA.
			Name: "mass-deletion",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				sel := "audit-mass=" + env.RunID
				labels := map[string]string{"audit-mass": env.RunID}
				pod := sleepPod("", env.Image, map[string]string{"app": "mass-deploy"})
				if _, err := env.Client.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "mass-deploy", Labels: labels},
					Spec: appsv1.DeploymentSpec{
						Replicas: int32p(0),
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "mass-deploy"}},
						Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "mass-deploy"}}, Spec: pod.Spec},
					},
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				for _, n := range []string{"mass-a", "mass-b"} {
					if _, err := env.Client.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: n, Labels: labels}}, metav1.CreateOptions{}); err != nil {
						return err
					}
					value := "MASS-SECRET-" + n + "-" + env.RunID
					env.AddMarker("mass secret "+n, value)
					if _, err := env.Client.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: n, Labels: labels}, StringData: map[string]string{"v": value}}, metav1.CreateOptions{}); err != nil {
						return err
					}
				}
				lo := metav1.ListOptions{LabelSelector: sel}
				if err := env.Client.AppsV1().Deployments(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, lo); err != nil {
					return err
				}
				if err := env.Client.CoreV1().ConfigMaps(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, lo); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if err := cl.CoreV1().Secrets(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, lo); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA deleting secrets, got %v", err)
				}
				return env.Client.CoreV1().Secrets(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, lo)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{Desc: "deployments deletecollection is logged", Requirement: ReqResources, Match: audit.Match{Verb: "deletecollection", Group: "apps", Resource: "deployments", Namespace: ns}, Level: "Request"},
					{Desc: "configmaps deletecollection is logged at Metadata", Requirement: ReqResources, Match: audit.Match{Verb: "deletecollection", Resource: "configmaps", Namespace: ns}, Level: "Metadata", RequestBody: audit.Forbidden},
					{Desc: "secrets deletecollection by an admin is logged at Metadata", Requirement: ReqSecrets, Match: audit.Match{Verb: "deletecollection", Resource: "secrets", Namespace: ns, ResponseCode: 200}, Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden},
					{Desc: "denied secrets deletecollection by a unprivileged SA is logged", Requirement: ReqAuthFail, Match: audit.Match{Verb: "deletecollection", Resource: "secrets", Namespace: ns, User: saUser(ns, saRestricted)}, Level: "Metadata", Code: 403, Annotations: forbidAnn},
				}
			},
		},
		{
			Name: "incident-kube-system-workload",
			Act: func(ctx context.Context, env *audit.Env) error {
				name := env.Name("ks")
				p := sleepPod(name, env.Image, map[string]string{"audit-test": env.RunID})
				p.Spec.NodeSelector = map[string]string{env.Label("never-schedule"): env.RunID}
				pods := env.Client.CoreV1().Pods("kube-system")
				if _, err := pods.Create(ctx, p, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := pods.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				value := "KUBE-SYSTEM-SECRET-" + env.RunID + "-do-not-log"
				env.AddMarker("kube-system secret value", value)
				secrets := env.Client.CoreV1().Secrets("kube-system")
				if _, err := secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}, StringData: map[string]string{"v": value}}, metav1.CreateOptions{}); err != nil {
					return err
				}
				if err := secrets.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
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
				if _, err := cl.CoreV1().Pods("kube-system").Create(ctx, sleepPod(name+"-denied", env.Image, nil), metav1.CreateOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA creating a kube-system pod, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				name := env.Name("ks")
				return []audit.Expect{
					{Desc: "workload created in kube-system by a human is logged with body", Requirement: ReqIncident, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: "kube-system", Name: name}, Level: "Request", RequestBody: audit.Required},
					{Desc: "kube-system pod delete is logged", Requirement: ReqIncident, Match: audit.Match{Verb: "delete", Resource: "pods", Namespace: "kube-system", Name: name}, Level: "Request"},
					{Desc: "secret planted in kube-system is logged at Metadata without value", Requirement: ReqSecrets, Match: audit.Match{Verbs: []string{"create", "delete"}, Resource: "secrets", Namespace: "kube-system", Name: name}, Level: "Metadata", RequestBody: audit.Forbidden, MinEvents: 2},
					{Desc: "denied kube-system pod create by a unprivileged SA is logged (403, no body, no name)", Requirement: ReqIncident, Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "-", Namespace: "kube-system", User: saUser(env.Namespace, saRestricted)}, Level: "Request", Code: 403, Annotations: forbidAnn, RequestBody: audit.Forbidden},
				}
			},
		},
		{
			// Node taints (kubectl taint) via update: two full-object updates,
			// the first of which carries the taint.
			Name: "node-taint",
			Act: func(ctx context.Context, env *audit.Env) error {
				if env.WorkerNode == "" {
					p, err := env.Client.CoreV1().Pods(env.Namespace).Get(ctx, podPlain, metav1.GetOptions{})
					if err != nil {
						return err
					}
					env.WorkerNode = p.Spec.NodeName
				}
				key := env.Label(env.RunID)
				nodes := env.Client.CoreV1().Nodes()
				setTaint := func(add bool) error {
					return retry.RetryOnConflict(retry.DefaultRetry, func() error {
						n, err := nodes.Get(ctx, env.WorkerNode, metav1.GetOptions{})
						if err != nil {
							return err
						}
						var taints []corev1.Taint
						for _, t := range n.Spec.Taints {
							if t.Key != key {
								taints = append(taints, t)
							}
						}
						if add {
							taints = append(taints, corev1.Taint{Key: key, Value: "true", Effect: corev1.TaintEffectPreferNoSchedule})
						}
						n.Spec.Taints = taints
						_, err = nodes.Update(ctx, n, metav1.UpdateOptions{})
						return err
					})
				}
				if err := setTaint(true); err != nil {
					return err
				}
				env.TaintedNode = env.WorkerNode
				if err := setTaint(false); err != nil {
					return err
				}
				env.TaintedNode = ""
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "node taint add/remove (full update) is logged with body", Requirement: ReqResources,
					Match: audit.Match{Verb: "update", Resource: "nodes", Subresource: "-", Name: env.WorkerNode},
					Level: "Request", RequestBody: audit.Required, MinEvents: 2,
					SomeRequestBodyContains: []string{env.Label(env.RunID), "PreferNoSchedule"},
				}}
			},
		},

		// ==================================================================
		// Things that must stay out of the log
		// ==================================================================
		{
			Name: "events-api-variants",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				ev := env.Client.EventsV1().Events(ns)
				if _, err := ev.Create(ctx, &eventsv1.Event{
					ObjectMeta: metav1.ObjectMeta{Name: "audit-event-v1"},
					Regarding:  corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: podPlain},
					Reason:     "AuditTest", Note: "events.k8s.io variant", Type: "Normal", Action: "Test",
					ReportingController: env.Label("test"), ReportingInstance: env.RunID,
					EventTime: metav1.NowMicro(),
				}, metav1.CreateOptions{}); err != nil {
					return err
				}
				// Most event fields are immutable; series is not.
				series := fmt.Sprintf(`{"series":{"count":2,"lastObservedTime":%q}}`, metav1.NowMicro().UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
				if _, err := ev.Patch(ctx, "audit-event-v1", types.MergePatchType, []byte(series), metav1.PatchOptions{}); err != nil {
					return fmt.Errorf("patch event: %w", err)
				}
				if _, err := env.Client.EventsV1().Events("").List(ctx, metav1.ListOptions{Limit: 10}); err != nil {
					return err
				}
				if err := ev.Delete(ctx, "audit-event-v1", metav1.DeleteOptions{}); err != nil {
					return err
				}
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Events(ns).List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA listing events, got %v", err)
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{Desc: "events.k8s.io create/patch/list/delete by a human are dropped", Requirement: ReqNoise, Match: audit.Match{Group: "events.k8s.io", Resource: "events"}, Level: "None"},
					{Desc: "denied event list by a unprivileged SA is dropped too (events are never logged)", Requirement: ReqNoise, Match: audit.Match{Resource: "events", User: saUser(env.Namespace, saRestricted)}, Level: "None"},
				}
			},
		},
		{
			Name: "watch-edge-cases",
			Act: func(ctx context.Context, env *audit.Env) error {
				ns := env.Namespace
				tok, err := tokenFor(ctx, env, ns, saRestricted)
				if err != nil {
					return err
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				if _, err := cl.CoreV1().Secrets(ns).Watch(ctx, metav1.ListOptions{TimeoutSeconds: int64p(2)}); !apierrors.IsForbidden(err) {
					return fmt.Errorf("expected 403 for restricted SA watching secrets, got %v", err)
				}
				w, err := env.Client.CoreV1().Pods(ns).Watch(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + podPlain, TimeoutSeconds: int64p(2)})
				if err != nil {
					return err
				}
				for range w.ResultChan() {
				}
				w, err = env.Client.CoreV1().ConfigMaps("").Watch(ctx, metav1.ListOptions{TimeoutSeconds: int64p(2)})
				if err != nil {
					return err
				}
				for range w.ResultChan() {
				}
				return nil
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				return []audit.Expect{
					{
						Desc: "denied secret watch by a unprivileged SA is logged (403, ResponseComplete only)", Requirement: ReqAuthFail,
						Match: audit.Match{Verb: "watch", Resource: "secrets", Namespace: ns, User: saUser(ns, saRestricted)},
						Level: "Metadata", Code: 403, Annotations: forbidAnn, Stages: []string{"ResponseComplete"},
					},
					{
						Desc: "single-object watch (fieldSelector metadata.name) is logged once", Requirement: ReqHumans,
						Match: audit.Match{Verb: "watch", Resource: "pods", Namespace: ns, URIContains: "fieldSelector=metadata.name"},
						Level: "Metadata", Stages: []string{"ResponseComplete"},
					},
					{
						Desc: "cluster-wide configmap watch by a human is logged once", Requirement: ReqHumans,
						Match: audit.Match{Verb: "watch", Resource: "configmaps", URIPrefix: "/api/v1/configmaps"},
						Level: "Metadata", Stages: []string{"ResponseComplete"},
					},
				}
			},
		},

		// ==================================================================
		// the proxy and Calico specifics (optional: skip if not installed)
		// ==================================================================
		{
			Name:     "authproxy-exec-and-secret-attribution",
			Optional: true,
			Needs:    needsProxy,
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.ProxySANamespace(), env.ProxySAName())
				if err != nil {
					return fmt.Errorf("mint token for %s/%s: %w", env.ProxySANamespace(), env.ProxySAName(), err)
				}
				cfg := tokenConfig(env, tok)
				cfg.Impersonate = rest.ImpersonationConfig{UserName: env.ProxyUser, Groups: env.ProxyGroups}
				cl, err := kubernetes.NewForConfig(cfg)
				if err != nil {
					return err
				}
				req := cl.CoreV1().RESTClient().Post().Resource("pods").Namespace(env.Namespace).Name(podPlain).SubResource("exec").
					VersionedParams(&corev1.PodExecOptions{Command: []string{"echo", "proxy-exec-" + env.RunID}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
				ex, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
				if err != nil {
					return err
				}
				if err := ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
					return fmt.Errorf("proxied user exec: %w", err)
				}
				if _, err := cl.CoreV1().Secrets(env.Namespace).Get(ctx, secretMounted, metav1.GetOptions{}); err != nil {
					return fmt.Errorf("proxied user secret get: %w", err)
				}
				if _, err := cl.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err != nil {
					return fmt.Errorf("proxied user namespace list: %w", err)
				}
				// The proxy account acting on its own, without impersonation.
				self, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				_, err = self.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "audit-proxy-self=1"})
				return ignoreForbidden(err)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				ns := env.Namespace
				proxy := saUser(env.ProxySANamespace(), env.ProxySAName())
				return []audit.Expect{
					{
						Desc: "exec through the proxy is logged with the end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: ns, Name: podPlain, User: proxy},
						Level: "Metadata", Impersonated: env.ProxyUser, ImpersonatedGroups: env.ProxyGroups,
					},
					{
						Desc: "secret read through the proxy is logged at Metadata with the end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "get", Resource: "secrets", Namespace: ns, Name: secretMounted, User: proxy},
						Level: "Metadata", RequestBody: audit.Forbidden, ResponseBody: audit.Forbidden, Impersonated: env.ProxyUser,
					},
					{
						Desc: "cluster-scoped read through the proxy is logged with the end-user identity", Requirement: ReqProxy,
						Match: audit.Match{Verb: "list", Resource: "namespaces", User: proxy, ImpersonatedUser: env.ProxyUser},
						Level: "Metadata",
					},
					{
						Desc: "the proxy account's own reads (no impersonation) are logged", Requirement: ReqProxy,
						Match: audit.Match{Verb: "list", Resource: "pods", Namespace: ns, User: proxy, URIContains: "audit-proxy-self"},
						Level: "Metadata", NoImpersonation: true,
					},
				}
			},
		},
		{
			Name:     "authproxy-other-sa-read-denied",
			Optional: true,
			Needs:    needsProxy,
			Act: func(ctx context.Context, env *audit.Env) error {
				tok, err := tokenFor(ctx, env, env.ProxySANamespace(), "default")
				if err != nil {
					return fmt.Errorf("mint token for %s/default: %w", env.ProxySANamespace(), err)
				}
				cl, err := clientWithToken(env, tok)
				if err != nil {
					return err
				}
				_, err = cl.CoreV1().Pods(env.Namespace).List(ctx, metav1.ListOptions{})
				return ignoreForbidden(err)
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{{
					Desc: "denied read by another SA of the proxy namespace is logged", Requirement: ReqAuthFail,
					Match: audit.Match{Verb: "list", Resource: "pods", Namespace: env.Namespace, User: saUser(env.ProxySANamespace(), "default")},
					Level: "Metadata", Code: 403,
					Gap: "section 3 drops all reads of system:serviceaccounts:" + env.ProxySANamespace() + " (only the clusterproxy SA is exempt); a stolen token of any other account in that namespace is invisible on reads",
				}}
			},
		},
		{
			// Writing directly to Calico's backing CRDs bypasses the
			// calico-apiserver and its validation: the body is visible here,
			// unlike through the aggregated projectcalico.org API.
			Name:     "calico-direct-crd-write",
			Optional: true,
			Needs:    needsCalico,
			Act: func(ctx context.Context, env *audit.Env) error {
				gvr := schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "networksets"}
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "crd.projectcalico.org/v1", "kind": "NetworkSet",
					"metadata": map[string]any{"name": "audit-netset", "namespace": env.Namespace},
					"spec":     map[string]any{"nets": []any{"192.0.2.0/24"}},
				}}
				if _, err := env.Dynamic.Resource(gvr).Namespace(env.Namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					return err
				}
				return env.Dynamic.Resource(gvr).Namespace(env.Namespace).Delete(ctx, "audit-netset", metav1.DeleteOptions{})
			},
			Expect: func(env *audit.Env) []audit.Expect {
				return []audit.Expect{
					{
						Desc: "direct write to a Calico backing CRD (bypassing calico-apiserver) is logged with body", Requirement: ReqResources,
						Match: audit.Match{Verb: "create", Group: "crd.projectcalico.org", Resource: "networksets", Namespace: env.Namespace, Name: "audit-netset"},
						Level: "Request", RequestBody: audit.Required, RequestBodyContains: []string{"192.0.2.0/24"},
					},
					{Desc: "direct Calico CRD delete is logged", Requirement: ReqResources, Match: audit.Match{Verb: "delete", Group: "crd.projectcalico.org", Resource: "networksets", Namespace: env.Namespace, Name: "audit-netset"}, Level: "Request"},
				}
			},
		},
	}
}

// TeardownScenarios run after namespace-delete and observe what the
// namespace-controller and the garbage collector write while tearing the
// test namespace down.
func TeardownScenarios() []Scenario {
	return []Scenario{{
		Name: "namespace-teardown-noise",
		Act: func(ctx context.Context, env *audit.Env) error {
			time.Sleep(4 * time.Second)
			return nil
		},
		Expect: func(env *audit.Env) []audit.Expect {
			ns := env.Namespace
			nsc := saUser("kube-system", "namespace-controller")
			return []audit.Expect{
				{
					// Deleting a namespace makes the namespace-controller sweep
					// every resource type in it: dozens of deletecollection
					// calls in a second. The bulk of them are ordinary
					// workload resources and must stay cheap.
					Desc: "namespace-controller sweeps of workload resources are Metadata without body", Requirement: ReqNoise,
					Match: audit.Match{
						Verbs: []string{"delete", "deletecollection"}, Namespace: ns, User: nsc, AnyUA: true,
						Resources: []string{"pods", "configmaps", "endpoints", "services", "persistentvolumeclaims", "podtemplates", "replicasets", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"},
					},
					Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true,
				},
				{
					// The security-relevant-writes rule outranks the rule that
					// quietens platform accounts, so the same sweep is logged
					// at Request for RBAC, networking and quota objects. That
					// is the policy working as intended: it is also the reason
					// a namespace deletion shows up as a burst of Request
					// events by a controller nobody invoked directly.
					Desc: "namespace-controller sweeps of security-relevant resources stay at Request", Requirement: ReqResources,
					Match: audit.Match{
						Verb: "deletecollection", Namespace: ns, User: nsc, AnyUA: true,
						Groups: []string{"rbac.authorization.k8s.io", "networking.k8s.io"},
					},
					Level: "Request", AllowNone: true,
				},
				{
					Desc: "namespace finalize by the namespace-controller is Metadata without body", Requirement: ReqNoise,
					Match: audit.Match{Verb: "update", Resource: "namespaces", Subresource: "finalize", Name: ns, User: nsc, AnyUA: true},
					Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true,
				},
				{
					Desc: "namespace-controller reads during teardown are dropped", Requirement: ReqNoise,
					Match: audit.Match{Verbs: []string{"get", "list", "watch"}, User: nsc, NotResources: []string{"secrets"}, AnyUA: true},
					Level: "None",
				},
			}
		},
	}}
}

// edgeGlobalExpectations are hygiene invariants over every event of the run.
func edgeGlobalExpectations(env *audit.Env) []audit.Expect {
	ks := func(sa string) string { return saUser("kube-system", sa) }
	return []audit.Expect{
		{Desc: "no event at level RequestResponse anywhere", Requirement: ReqHygiene, Match: audit.Match{Level: "RequestResponse", AnyUA: true}, Level: "None"},
		{Desc: "no event carries a responseObject", Requirement: ReqHygiene, Match: audit.Match{AnyUA: true}, ResponseBody: audit.Forbidden},
		{Desc: "writes by kubelets are Metadata at most", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"create", "update", "patch", "delete"}, UserGroup: "system:nodes", AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true},
		{Desc: "garbage collector deletes are Metadata without body", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"delete", "deletecollection", "patch", "update"}, User: ks("generic-garbage-collector"), AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true},
		{Desc: "endpointslice churn by the endpointslice-controller is Metadata without body", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"create", "update", "patch", "delete"}, Group: "discovery.k8s.io", User: ks("endpointslice-controller"), AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true},
		{Desc: "endpoints churn by the endpoints-controller is Metadata without body", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"create", "update", "patch", "delete"}, Resource: "endpoints", UserGroup: "system:serviceaccounts:kube-system", AnyUA: true}, Level: "Metadata", RequestBody: audit.Forbidden, AllowNone: true},
		{Desc: "kube-proxy traffic is dropped", Requirement: ReqNoise, Match: audit.Match{User: ks("kube-proxy"), AnyUA: true}, Level: "None"},
		{Desc: "cloud-controller-manager reads and heartbeats are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"get", "list", "watch"}, User: ks("cloud-controller-manager"), NotResources: []string{"secrets"}, AnyUA: true}, Level: "None"},
		{Desc: "cert-manager reads and heartbeats are dropped", Requirement: ReqNoise, Match: audit.Match{Verbs: []string{"get", "list", "watch"}, UserGroup: "system:serviceaccounts:k8s-svc-cert-manager", NotResources: []string{"secrets"}, AnyUA: true}, Level: "None"},
	}
}

// cleanupEdge removes what the edge scenarios may leave behind after an
// aborted run; the test namespace itself is deleted by cleanup.
func cleanupEdge(ctx context.Context, env *audit.Env, try func(string, error)) {
	c := env.Client
	del := metav1.DeleteOptions{}
	name := env.Name("ks")
	try("kube-system pod", c.CoreV1().Pods("kube-system").Delete(ctx, name, del))
	try("kube-system secret", c.CoreV1().Secrets("kube-system").Delete(ctx, name, del))
	try("edge crd", env.Dynamic.Resource(crdGVR).Delete(ctx, edgeCRDName(env), del))
	if env.TaintedNode != "" {
		key := env.Label(env.RunID)
		try("node taint", retry.RetryOnConflict(retry.DefaultRetry, func() error {
			n, err := c.CoreV1().Nodes().Get(ctx, env.TaintedNode, metav1.GetOptions{})
			if err != nil {
				return err
			}
			var taints []corev1.Taint
			for _, t := range n.Spec.Taints {
				if !strings.HasPrefix(t.Key, key) {
					taints = append(taints, t)
				}
			}
			n.Spec.Taints = taints
			_, err = c.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{})
			return err
		}))
	}
}
