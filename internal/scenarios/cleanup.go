package scenarios

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/beardedLegend/k8-apt/internal/audit"
)

// Cleanup removes everything the scenarios may have left behind, so that an
// interrupted run does not litter the cluster. Objects a scenario deleted
// itself are simply not found. try reports the failures it cannot fix.
func Cleanup(ctx context.Context, env *audit.Env, try func(what string, err error)) {
	c := env.Client
	del := metav1.DeleteOptions{}
	name := env.Name("obj")
	try("namespace", c.CoreV1().Namespaces().Delete(ctx, env.Namespace, del))
	try("clusterrolebinding", c.RbacV1().ClusterRoleBindings().Delete(ctx, env.Name("cr"), del))
	try("clusterrole", c.RbacV1().ClusterRoles().Delete(ctx, env.Name("cr"), del))
	try("escalation clusterrolebinding", c.RbacV1().ClusterRoleBindings().Delete(ctx, env.Name("pwn"), del))
	try("denied-escalation clusterrolebinding", c.RbacV1().ClusterRoleBindings().Delete(ctx, env.Name("escalate"), del))
	try("tamper validatingwebhookconfiguration", c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, env.Name("tamper"), del))
	try("csr", c.CertificatesV1().CertificateSigningRequests().Delete(ctx, env.Name("csr"), del))
	try("kube-system configmap", c.CoreV1().ConfigMaps("kube-system").Delete(ctx, env.Name("cm"), del))
	try("kube-system serviceaccount", c.CoreV1().ServiceAccounts("kube-system").Delete(ctx, env.Name("sa"), del))
	try("storageclass", c.StorageV1().StorageClasses().Delete(ctx, name, del))
	try("priorityclass", c.SchedulingV1().PriorityClasses().Delete(ctx, name, del))
	try("runtimeclass", c.NodeV1().RuntimeClasses().Delete(ctx, name, del))
	try("persistentvolume", c.CoreV1().PersistentVolumes().Delete(ctx, name, del))
	try("mutatingwebhookconfiguration", c.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, name, del))
	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	try("crd", env.Dynamic.Resource(crdGVR).Delete(ctx, "audittests."+env.Domain, del))
	cleanupEdge(ctx, env, try)
	key := env.Label(env.RunID)
	if nodes, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: key}); err == nil {
		for _, n := range nodes.Items {
			_, err := c.CoreV1().Nodes().Patch(ctx, n.Name, types.MergePatchType,
				fmt.Appendf(nil, `{"metadata":{"labels":{%q:null}}}`, key), metav1.PatchOptions{})
			try("node label", err)
		}
	}

}
