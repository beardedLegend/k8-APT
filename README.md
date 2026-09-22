# k8-apt — Kubernetes audit policy tester

An audit policy is a guess until something checks it. `k8-apt` exercises a
live cluster with the requests a real day produces — and with the ones an
attacker would make — then reads the API server's audit log and reports what
the policy actually recorded.

```console
$ k8-apt run --config cluster.yaml --idle-sample 10m

  COVERAGE BY REQUIREMENT
  requirement                                       pass fail diff  gap skip
  ──────────────────────────────────────────────────────────────────────────
  R01 resource creation and modification              63    0    0    1    0  ⚠
  R03 container execution (exec/attach/portforward)    8    0    0    0    0  ✓
  R05 authn/authz failures                            11    0    0    4    2  ⚠
  R09 access to secrets (without secret data)         18    0    0    0    0  ✓
  ...

  LOG VOLUME BUDGET  36.5 GB/year = 100.0 MB/day
  idle     3.4 MB/day → 1.24 GB/year  (18 background events in 10m1s)
  headroom 96.6 MB/day ≈ 78083 events of this run's average size

  PASS (with known gaps)   313 passing · 0 failing · 0 differing · 5 gaps · 2 skipped
```

It answers the questions you cannot answer by reading the policy file:

* Is everything a human does on the cluster actually recorded?
* Do privileged pods, RBAC grants and admission-webhook changes keep their
  body, so the log says *what* changed and not just *that* something did?
* Do secrets and tokens get logged **without** their contents — including
  through server-side apply, dry-run and the token controller?
* Are failed and denied requests visible, with who tried what?
* Is an authenticating proxy's end user named in the log, or does the policy
  attribute their actions to the proxy — or drop them entirely?
* Does the cluster's background noise fit the log volume you can afford to
  keep for a year?

## Installing

```sh
go install github.com/beardedLegend/k8-apt/cmd/k8-apt@latest
```

or from a checkout:

```sh
go build -o k8-apt ./cmd/k8-apt
```

## Running

```sh
k8-apt run --config cluster.yaml
```

A run takes about 80 seconds plus `--idle-sample`. It needs:

* **cluster-admin**, or close to it. The run creates a throw-away namespace, a
  few uniquely named cluster-scoped objects (StorageClass, PriorityClass,
  RuntimeClass, PersistentVolume, CRDs, admission webhook configurations,
  ClusterRoles and bindings, a CSR), service accounts with tokens, a taint and
  a label on one node — and deletes all of it again, including after an
  interrupted run.
* **Read access to the audit log.** By default it discovers the control plane
  nodes through the API and reads `/var/log/kubernetes/audit/audit.log` from
  each over ssh with `sudo`, non-interactively. `--log-files` verifies an
  exported log instead.
* **A pullable image** for the test pods (`busybox:1.36` by default). A
  handful of pods actually start; the rest are made deliberately
  unschedulable.

Nothing is truncated: the run records where each log stands at the start and
only reads what is appended afterwards. Every request carries the User-Agent
`k8-apt/<runid>` and every object it creates has that run id in its name, so
its own traffic can always be told apart from the cluster's.

### Commands

| Command | |
|---|---|
| `k8-apt run` | run the scenarios and report |
| `k8-apt scenarios` | list the scenarios that apply to a profile |
| `k8-apt config` | print the effective profile, defaults filled in |
| `k8-apt version` | print the version |

### Flags of `run`

| Flag | |
|---|---|
| `--config` | cluster profile (see below); defaults apply when unset |
| `--kubeconfig` | kubeconfig to use (default `$KUBECONFIG`, then `~/.kube/config`) |
| `--strict` | fail on any difference from the baseline policy, not only on invariants |
| `--idle-sample` | idle this long first, to measure the background log volume (e.g. `10m`) |
| `--only` | comma-separated substrings; run only the matching scenarios |
| `--log-files` | verify local audit log files instead of reading the cluster |
| `--budget` | log volume budget in GB per cluster per year |
| `--events-file` | write every audit event of the run here (JSON lines) |
| `--report` | write the full report as markdown here |
| `--json` | machine-readable results, for CI |
| `--color` | `auto`, `always` or `never` |
| `--quiet` | no progress output |

The exit code is non-zero when the run fails (see *Result semantics*).

### From CI, as a Go test

The same run is available as a `go test`, so each expectation becomes a
subtest and a failure names the scenario and the check that broke:

```sh
K8APT_CONFIG=cluster.yaml K8APT_STRICT=1 go test -count=1 -timeout 30m -v ./...
```

`K8APT_IDLE`, `K8APT_REPORT` and `K8APT_EVENTS` mirror the flags above. The
unit tests (`go test ./internal/...`) need no cluster at all.

## Configuring

Everything the tool cannot discover for itself lives in a cluster profile.
An empty profile is a valid profile: see [`examples/minimal.yaml`](examples/minimal.yaml)
for the short form and [`examples/annotated.yaml`](examples/annotated.yaml)
for every field with its default and what it is for.

```yaml
# cluster.yaml
testDomain: audit-test.example.com   # for the labels and CRDs the run creates
idleSample: 10m
log:
  sshUser: ubuntu
  path: /var/log/kubernetes/audit/audit.log
budget:
  gbPerYear: 36.5
expect:
  managedGroups:                     # groups the policy treats as platform
    - system:nodes
    - system:serviceaccounts:kube-system
    - system:serviceaccounts:ingress-nginx
components:
  proxy:                             # a VPN gateway, SSO portal, access broker
    enabled: true
    serviceAccountNamespace: access-proxy
    serviceAccountName: cluster-proxy
    groups: [platform-admins]
  calico:
    enabled: true
```

The tool works out the rest: who you authenticate as (a `SelfSubjectReview`,
so certificates, OIDC and external CAs all work), which nodes are control
plane nodes, and which scenarios apply.

## Result semantics

Expectations come in two tiers, because "what the policy should do" is partly
a matter of taste and partly not:

* **Invariant** — true of any audit policy worth running: secret values and
  issued tokens never appear in the log, bodies never carry `managedFields`.
  A failure is a real finding whatever policy you run, and always fails the
  run.
* **Baseline** — true of [`policy/baseline.yaml`](policy/baseline.yaml), the
  policy shipped here. On a cluster running a different policy a failure may
  simply be a deliberate difference, so it is reported as `DIFF` and only
  fails the run under `--strict`.

Alongside those:

* **GAP** — a documented limitation of the baseline policy, reported but never
  fatal. When the policy changes so the expectation passes, it flips to "gap
  closed", which is how you notice you fixed one.
* **SKIP** — the scenario could not run on this cluster (no in-cluster signer
  for client certificates, for instance).

So: **start without `--strict`**, read the `DIFF` list as "here is how your
policy differs from the baseline", decide which differences you meant, encode
those in the profile's `expect:` section — then turn on `--strict` in CI and
keep it green.

## The baseline policy

[`policy/baseline.yaml`](policy/baseline.yaml) is the policy the default
expectations describe, and a reasonable starting point in its own right:
human and workload activity logged, security-relevant writes with their body,
credentials without their contents, component chatter dropped. It is
commented throughout, including its two known limitations, and marks the lists
you need to adapt to your cluster.

## What it covers

| | Scenarios |
|---|---|
| Resource lifecycle: pods, deployments, StatefulSets, DaemonSets, HPAs, jobs, cronjobs, services, ingresses, PVCs, network policies, quotas, PDBs, configmaps, namespaces, cluster-scoped objects, CRDs and custom resources | `namespace-*`, `pod-*`, `deployment-lifecycle`, `workload-controllers`, `job-cronjob-lifecycle`, `service-ingress-pvc-networkpolicy`, `quota-limitrange-pdb`, `configmap-*`, `cluster-scoped-objects`, `custom-resources` |
| RBAC: Roles, RoleBindings, ClusterRoles, bindings, and the escalation checks that reject them | `rbac-lifecycle`, `rbac-escalation-prevention` |
| Interactive access: exec (SPDY and WebSocket), attach, port-forward, logs (incl. `-f`, `--previous`, `--tail`), ephemeral containers, pods/nodes/services proxy | `pod-exec-attach-portforward`, `pod-ephemeral-container`, `proxy-subresources`, `logs-follow-previous-tail` |
| Privileged workloads: privileged, hostPID, hostNetwork, hostPath, by a human and by a workload account | `pod-create-privileged`, `workload-sa-privileged-pod`, `incident-rogue-workload-hostmount` |
| Authentication and authorization failures: 401s, 403s, denied reads and writes, basic auth, empty and expired tokens, deleted service accounts | `authn-failure`, `authn-edge-cases`, `authz-failure-unprivileged-sa`, `kube-system-sa-denied`, `csr-cert-user-denied` |
| Anonymous access: resources, discovery, health, `/`, HEAD and OPTIONS, writes, exec | `anonymous`, `anonymous-extended` |
| Impersonation: `--as`, groups, uid, extra, anonymous, malformed headers, denied attempts | `impersonation`, `impersonation-edge-cases`, `impersonation-groups-recorded` |
| Credentials: TokenRequest, CSR issue/approve/delete, legacy token secrets, secret volumes, mass secret reads | `serviceaccount-token-issuance`, `csr-issuance`, `token-lateral-movement`, `pod-with-secret-volume`, `secret-lifecycle` |
| Everyday operator work: server-side apply, dry-run, chunked lists and selectors, leases, `auth whoami` / `can-i --list`, node labels and taints, manual bindings, status writes | `server-side-apply`, `dry-run`, `pagination-and-selectors`, `leases-by-humans-and-workload-sa`, `identity-introspection`, `node-label`, `node-taint`, `pod-status-and-manual-binding` |
| Error paths and probing: 400, 404, 405, 409, 415, 422, unknown resources and groups, pprof, JWKS, metrics | `error-responses`, `api-probing` |
| Noise that must stay out: health probes, discovery, events, lease heartbeats, status writes, controller and kubelet reads, garbage collection, namespace teardown, kube-proxy | global expectations plus the `*-are-dropped` checks inside the scenarios |
| Hygiene: no `RequestReceived`, no `managedFields`, no bodies on secrets, tokens or token reviews, no leaked values | global expectations, `no-credential-leak` |
| An authenticating proxy: reads, writes, exec and secrets by the end user behind it | `authproxy-*` |
| Simulated incidents: privilege escalation, RBAC self-grant, secret exfiltration, rogue node, container breakout, lateral movement into the control plane namespace, admission-webhook tampering, mass deletion | `incident-*`, `mass-deletion` |
| Log volume against the yearly budget | global `log-budget` |

## Things worth knowing about audit logs

Findings from running this against real clusters, useful when reading a log or
writing detection rules:

* **The audit policy is matched against the real user, not the impersonated
  one.** This is the opposite of authorization, and it is why an authenticating
  proxy whose service account is treated as a platform component makes every
  end user behind it invisible or bodyless. `authproxy-*` exists for this.
* **Server-side apply is `patch`**, whether it creates or updates. There is no
  `create` event for an object that was applied into existence.
* **Dry-run requests are logged like real ones.** A dry-run create carries
  `dryRun=All` in the URI; a dry-run *delete* does not, because the option
  travels in the `DeleteOptions` body.
* **Errors keep their body where it matters**: a 422 validation failure, a 409
  conflict and an RBAC escalation 403 all carry the decoded request. A 400, a
  415 and a 403 from authorization do not — and have no `objectRef.name`,
  because the name lives in the body that was never decoded.
* **RBAC escalation prevention answers 403 with
  `authorization.k8s.io/decision: allow`** — authorization allowed it, the
  registry refused it. A detection rule keyed on `decision=forbid` misses
  every escalation attempt; key on `code=403`.
* **Denied impersonation carries no decision annotation at all**, and no
  `impersonatedUser`: the identity that was attempted lives only in request
  headers, which are not logged.
* **Failed authentication is audited at `ResponseStarted` only.** Any rule
  with `omitStages: [ResponseStarted]` — which is the usual way to log a watch
  once — silently hides 401s against the resources it covers.
* **Dropping reads by a group also drops their denied reads.** A rule that
  filters component chatter cannot distinguish a controller doing its job from
  a stolen component token probing the API, because the drop happens before
  the authorization outcome is known.
* **Aggregated APIs cannot record bodies.** The API server only proxies the
  request, so `Request` level yields events that look like `Metadata`. The
  aggregated server needs its own audit policy.
* **Long-running reads produce two events** (`ResponseStarted` and
  `ResponseComplete`); watches produce one. Anonymous `HEAD /` and `OPTIONS /`
  are logged under the lowercased HTTP method as the verb, so a load-balancer
  probe drop written for `get` will not match them.
* **Pods created through `generateName`** have no `objectRef.name`; correlate
  through the owning ReplicaSet.
* **Deleting a namespace is loud.** The namespace controller sweeps every
  resource type in it — around 45 `deletecollection` calls in a second — and
  a dozen of them land at `Request` level, because a rule that keeps bodies
  for RBAC and networking outranks the rule that quietens platform accounts.
  Worth knowing before you conclude that a controller went rogue.

## Log volume

Retention rules (ISO 27001 asks for twelve months) turn "log everything" into
a storage bill, so every run measures what the cluster costs. Events the run
did not cause are background; their volume over the sample is extrapolated to
a day and a year and compared to `budget.gbPerYear`. The report gives the idle
rate, the headroom left for real work, the run's own cost, and the largest
background contributors as `user verb resource` — which is the list to work
down when a cluster is over budget.

Use `--idle-sample 10m`: the run then idles first and measures the quiet
window before it acts. Without it the sample is the run itself, which is short
and counts the cluster's reactions to the run as background, so the figure is
indicative only and never fails the run.

For scale, on a small cluster (7 nodes, Calico, cert-manager, ingress): an
unfiltered `level: Metadata` policy produced 127 MB/day (46 GB/year); a policy
of this shape produced 3–5 MB/day (1.2–1.8 GB/year).

## How it is put together

```
cmd/k8-apt         the binary
internal/audit     event model, matchers, expectations, verification, log sources
internal/scenarios what the run does and what it then expects (core.go, edge.go)
internal/budget    log volume measurement
internal/report    terminal and markdown reports
internal/runner    act → fetch → verify → report
internal/config    the cluster profile
policy/baseline.yaml   the policy the default expectations describe
```

A scenario has two halves, and they run at different times: every `Act` runs
first, then the log is fetched **once**, then every `Expect` is checked against
it. That is why an expectation can assert things about events the scenario did
not cause itself — a controller reacting to it, a kubelet, another node — and
why the whole run needs only one pass over the log.

Adding one means appending a `Scenario` to `internal/scenarios`: make the
requests in `Act`, declare what must show up in `Expect`, give every
expectation a `Requirement` so it lands in the coverage table, and mark it
`Tier: audit.Invariant` if it holds for any policy rather than only for the
baseline. `go test ./internal/...` checks the shape of every scenario without
needing a cluster.

## Safety

The run is designed to be safe on a cluster that matters, but it is not
read-only, so read this once before pointing it at production:

* Everything it creates is uniquely named with the run id and deleted again,
  including after an interruption or a failure.
* It never modifies an object it did not create, with two exceptions: it adds
  and removes a label and a taint on one node (both namespaced to the test
  domain, both removed in cleanup).
* The breakout and host-mount pods are made permanently unschedulable, so they
  never actually run anywhere.
* It never reads the value of a secret it did not create: the secret scenarios
  read their own, and the exfiltration scenario lists metadata only.
* The incident scenarios create and immediately delete their own inert objects
  (a ClusterRoleBinding to a principal that does not exist, an admission
  webhook pointing at an unreachable URL with `failurePolicy: Ignore`).
* It does create real load for a minute or so, and it writes to `kube-system`
  (a ConfigMap, a ServiceAccount, an unschedulable pod, a secret — all deleted).

## Licence

see [LICENSE](./LICENSE)
