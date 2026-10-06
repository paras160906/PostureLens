# Falco Runtime Monitoring Setup Guide

This guide describes how to deploy **Falco** to a local Kubernetes cluster (**Minikube** or **Kind**) and configure it to stream runtime security alerts directly into the **PostureLens** backend.

---

## 1. Prerequisites

- Local Kubernetes cluster running via **Minikube** or **Kind**.
- `kubectl` configured to interact with your cluster.
- `helm` (v3+) installed.
- PostureLens API running on your host machine at `http://<HOST_IP>:8000`.

---

## 2. Installing Falco via Helm

Add the official Falco Helm repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Create a namespace for Falco:

```bash
kubectl create namespace falco
```

---

## 3. Configuring Falco to Stream Alerts to PostureLens

Falco supports streaming alerts as structured JSON over HTTP webhooks using `http_output`.

Create a custom values file named `falco-values.yaml`:

```yaml
# falco-values.yaml
driver:
  kind: modern_ebpf

falco:
  # Enable JSON formatted alert output
  json_output: true
  json_include_output_property: true
  json_include_tags_property: true
  
  # Enable HTTP Output Webhook pointing to PostureLens API
  http_output:
    enabled: true
    # Replace <HOST_IP> with your local workstation IP address (e.g. 192.168.1.50 or host.minikube.internal)
    url: "http://host.minikube.internal:8000/falco/webhook"
    user_agent: "falcosecurity/falco"

# Enable Kubernetes Audit Log and metadata collection
collectors:
  k8s_metadata:
    enabled: true

# Custom Security Rules
customRules:
  custom-rules.yaml: |
    - rule: Terminal Shell in Container
      desc: A terminal shell (bash/sh/zsh) was spawned inside a running container
      condition: container.id != host and proc.name in (bash, sh, zsh, ksh, csh) and container.name != ""
      output: >
        Terminal shell spawned in container (user=%user.name user_uid=%user.uid container_id=%container.id
        container_name=%container.name image=%container.image.repository:%container.image.tag
        pod=%k8s.pod.name ns=%k8s.ns.name cmdline=%proc.cmdline)
      priority: CRITICAL
      tags: [container, shell, mitre_execution]

    - rule: Sensitive File Read in Container
      desc: Detection of sensitive system file access (e.g. /etc/shadow or /etc/passwd)
      condition: open_read and container.id != host and fd.name in (/etc/shadow, /etc/sudoers)
      output: >
        Sensitive file opened for reading (user=%user.name file=%fd.name command=%proc.cmdline
        container_id=%container.id image=%container.image.repository pod=%k8s.pod.name ns=%k8s.ns.name)
      priority: HIGH
      tags: [container, file_access, mitre_credential_access]
```

---

## 4. Deploying Falco to Minikube / Kind

### For Minikube:
Ensure host access is enabled so containers inside Minikube can reach host port 8000 using `host.minikube.internal`:

```bash
helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco-values.yaml
```

### For Kind:
For Kind clusters, use `host.docker.internal` or your machine's LAN IP address (`http://192.168.x.x:8000/falco/webhook`).

```bash
helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco-values.yaml
```

---

## 5. Verifying Deployment & Live Ingestion

1. Verify Falco pods are running:
   ```bash
   kubectl get pods -n falco
   ```

2. Trigger a test runtime violation inside a test container:
   ```bash
   kubectl run -it --rm debug-pod --image=alpine -- sh
   ```

3. Open the PostureLens UI at `http://localhost:3000` and navigate to the **Runtime Alerts** tab.
   You will see live runtime alerts ingested, normalized, and displayed with real-time polling!

---

## 6. Architecture Diagram

```
+-----------------------------------+
|  Minikube / Kind K8s Cluster      |
|                                   |
|  +-----------------------------+  |
|  |  Falco eBPF Kernel Probe    |  |
|  +--------------+--------------+  |
|                 |                 |
|                 v (JSON Alert)    |
+-----------------|-----------------+
                  |
                  |  HTTP POST /falco/webhook
                  v
+-----------------------------------+
|  PostureLens Backend (Port 8000)  |
|                                   |
|  - FalcoAlertNormalizer           |
|  - SQLite Database (runtime_alerts)|
|  - GET /runtime-alerts            |
+-----------------+-----------------+
                  |
                  |  Polling (every 5s)
                  v
+-----------------------------------+
|  React Frontend UI (Port 3000)    |
|  - "Runtime Alerts" Dashboard Tab |
+-----------------------------------+
```
