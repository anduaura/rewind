# Kubernetes deployment guide

rewind runs as a DaemonSet — one pod per node — so it captures traffic from every workload on the node without any per-service configuration.

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes 1.24+ | Earlier versions may work but are untested |
| Linux 5.10+ on nodes | `kubectl get nodes -o wide` shows the OS image |
| Helm 3.x | For chart-based install |
| Privileged containers allowed | Required for eBPF; most managed clusters permit this |
| Container runtime | containerd or CRI-O (dockershim removed in k8s 1.24) |

## Install with Helm

```bash
helm install rewind helm/rewind \
  --namespace rewind \
  --create-namespace \
  --set image.repository=ghcr.io/anduaura/rewind \
  --set image.tag=0.1.0
```

Verify the DaemonSet is running on all nodes:

```bash
kubectl get pods -n rewind -o wide
```

```
NAME           READY   STATUS    NODE
rewind-4xk9p   1/1     Running   node-1
rewind-7bmq2   1/1     Running   node-2
rewind-j9n3f   1/1     Running   node-3
```

### Helm values

| Value | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/anduaura/rewind` | Container image |
| `image.tag` | `0.1.0` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `resources.requests.memory` | `128Mi` | Ring buffer is ~50–100 MB |
| `resources.limits.memory` | `256Mi` | |
| `config.ringMaxEvents` | `200000` | ~5 minutes at 1k req/s |
| `config.captureBodyBytes` | `false` | Enable body capture |
| `config.logFormat` | `json` | `text` or `json` |
| `serverToken` | `""` | Bearer token for the collection server |
| `tolerations` | `[]` | Add tolerations for tainted nodes |

Example values file for a production deployment:

```yaml
# values-prod.yaml
image:
  tag: 0.1.0

config:
  logFormat: json
  ringMaxEvents: 400000   # ~10 minutes

resources:
  requests:
    memory: 200Mi
  limits:
    memory: 400Mi

serverToken: "your-secret-token"

tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
```

```bash
helm install rewind helm/rewind -n rewind --create-namespace -f values-prod.yaml
```

### Alternative: raw manifests

```bash
kubectl apply -k k8s/
```

## Capturing a snapshot after an incident

### Method 1 — exec into the pod on the affected node

Find which node handled the incident (from your logs or APM), then exec into the rewind pod on that node:

```bash
# Find the rewind pod on the affected node
NODE="node-2"
POD=$(kubectl get pod -n rewind -l app.kubernetes.io/name=rewind \
        --field-selector spec.nodeName=$NODE \
        -o jsonpath='{.items[0].metadata.name}')

# Flush the last 5 minutes of traffic
kubectl exec -n rewind $POD -- \
  rewind flush --window 5m --output /tmp/incident.rwd

# Copy it to your machine
kubectl cp rewind/$POD:/tmp/incident.rwd ./incident.rwd
```

### Method 2 — auto-trigger via PagerDuty / Opsgenie webhook

rewind can flush automatically when an alert fires. Start the webhook listener in the pod:

```bash
kubectl exec -n rewind $POD -- \
  rewind webhook --listen 0.0.0.0:9091 --output-dir /tmp/snapshots --window 5m \
  --hmac-secret "$PAGERDUTY_WEBHOOK_SECRET"
```

Then configure PagerDuty to POST to `http://<node-ip>:9091/flush` on alert open.

The snapshot is written to `/tmp/snapshots/<timestamp>.rwd` automatically.

### Method 3 — push to the central collection server

Run a collection server so agents push snapshots automatically without `kubectl cp`:

```bash
# Deploy the server (separate Deployment, not DaemonSet)
kubectl apply -f k8s/server.yaml

# Configure agents to push on flush
kubectl set env daemonset/rewind -n rewind \
  REWIND_SERVER_URL=http://rewind-server:9092 \
  REWIND_SERVER_TOKEN=your-token
```

Then download from the server:

```bash
# List snapshots
curl -H "Authorization: Bearer your-token" http://rewind-server:9092/snapshots

# Download one
curl -H "Authorization: Bearer your-token" \
  http://rewind-server:9092/snapshots/incident-20260424-102301.rwd \
  -o incident.rwd
```

## Replaying locally

Once you have `incident.rwd` on your machine, replay it against a local Docker Compose stack that mirrors your Kubernetes service:

```bash
rewind inspect incident.rwd   # see what services are involved

rewind replay incident.rwd --compose docker-compose.yml
```

You don't need Kubernetes installed locally. The replay engine brings up Docker containers, mocks all outbound calls with recorded responses, and re-fires the triggering request.

## Service attribution

rewind maps container PIDs to service names so events are labelled correctly in `rewind inspect` output and reports. In Kubernetes it does this through three layers (tried in order):

1. **`crictl ps`** — reads pod labels (`app`, `app.kubernetes.io/name`, `component`) for all running containers at agent startup. This is the primary source.

2. **Extended cgroup parsing** — reads `/proc/<pid>/cgroup` and extracts container IDs from `cri-containerd-` and `crio-` paths (containerd and CRI-O runtimes).

3. **`HOSTNAME` environment variable** — falls back to reading `HOSTNAME` from `/proc/<pid>/environ`. In Kubernetes, `HOSTNAME` equals the pod name. rewind strips the ReplicaSet hash suffix (`api-7d9f8b64c-xk2p9` → `api`) to recover the workload name.

If events show `service: ""`, check:

```bash
# Does crictl work on the node?
kubectl exec -n rewind $POD -- crictl ps --output json | head -20

# Are pods labelled with 'app' or 'app.kubernetes.io/name'?
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.labels}{"\n"}{end}'
```

## RBAC

The Helm chart creates a `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding` with the minimum permissions rewind needs:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get", "list"]
```

This allows rewind to query the kubelet API as a fallback for service name resolution. No write permissions are granted.

## Multi-node snapshots

Each rewind pod captures traffic only on its own node. For incidents that span multiple nodes:

1. Flush snapshots from each affected node.
2. Merge them into a single timeline using the collection server (snapshots from all agents are correlated by `traceparent` / `X-Request-ID` headers).
3. Or inspect them individually — rewind preserves trace IDs so you can match spans across snapshots.

```bash
# Flush from all nodes simultaneously
for POD in $(kubectl get pod -n rewind -l app.kubernetes.io/name=rewind \
               -o jsonpath='{.items[*].metadata.name}'); do
  kubectl exec -n rewind $POD -- \
    rewind flush --window 5m --output /tmp/incident.rwd &
done
wait

# Copy from each
for i in 1 2 3; do
  POD=$(kubectl get pod -n rewind -o jsonpath="{.items[$((i-1))].metadata.name}")
  kubectl cp rewind/$POD:/tmp/incident.rwd ./incident-node$i.rwd
done
```

## Health and metrics

The agent exposes Prometheus metrics on `:9090`:

```bash
kubectl port-forward -n rewind daemonset/rewind 9090:9090
curl http://localhost:9090/metrics
curl http://localhost:9090/healthz
```

Key metrics:

| Metric | Description |
|---|---|
| `rewind_http_events_total` | HTTP events captured since start |
| `rewind_db_events_total` | DB events captured since start |
| `rewind_ring_buffer_size` | Current ring buffer occupancy |
| `rewind_ring_buffer_utilization` | Fraction of ring capacity used (0–1) |
| `rewind_flushes_total` | Number of snapshot flushes |

Pre-built Grafana dashboards are in `grafana/dashboards/`. Import them via the Grafana UI or provision them with the bundled datasource config.

## Uninstall

```bash
helm uninstall rewind -n rewind
kubectl delete namespace rewind
```

## Troubleshooting

### Pods stuck in `Pending`

The DaemonSet requires `hostPID: true` and a privileged security context. If your cluster uses a PodSecurityPolicy or Pod Security Admission, add an exemption:

```bash
kubectl label namespace rewind pod-security.kubernetes.io/enforce=privileged
```

### `failed to attach kprobe to tcp_sendmsg`

The kernel BTF (BPF Type Format) must be available at `/sys/kernel/btf/vmlinux`. Most distributions ship this by default from kernel 5.8+. If missing:

```bash
# Check BTF availability
ls -la /sys/kernel/btf/vmlinux
```

On Amazon Linux 2023 or RHEL 9, BTF is available. On older AMIs, upgrade to a kernel that includes BTF.

### Events captured but service names show `""`

See [Service attribution](#service-attribution) above. The most common fix is to ensure pods have an `app` or `app.kubernetes.io/name` label:

```yaml
# deployment.yaml
metadata:
  labels:
    app: api   # rewind reads this label
spec:
  template:
    metadata:
      labels:
        app: api
```
