# Pulumi OPA Policy Bridge

> Write infrastructure policies in [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and enforce them during Pulumi deployments

## Why Use OPA with Pulumi?

Define security, compliance, and best practice policies in Rego and enforce them **before** resources are deployed. Catch violations during `pulumi preview`, not after deployment. Policies apply to any Pulumi provider -- AWS, Azure, GCP, Kubernetes, and the entire ecosystem.

## Quick Example

**Policy** (prevents public S3 buckets):
```rego
package aws

# METADATA
# title: No Public S3 Buckets
# description: S3 buckets must not use public-read ACLs.
# custom:
#   message: Set the ACL to 'private' or remove it entirely.
deny_public_buckets[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not be publicly accessible", [input.__name])
}
```

**Usage**:
```bash
# Run Pulumi with your policy pack
pulumi preview --policy-pack ./policies

# Output:
# Policy Violations:
#   [mandatory] No Public S3 Buckets
#   S3 bucket 'my-bucket' must not be publicly accessible
```

**Result**: Deployment is blocked until the violation is fixed.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Policy Examples](#policy-examples)
- [Resource Input Structure](#resource-input-structure)
- [Kubernetes Admission Controller Compatibility](#kubernetes-admission-controller-compatibility)
- [Stack-Level Policies](#stack-level-policies)
- [Policy Configuration](#policy-configuration)
- [Policy Metadata (OPA Annotations)](#policy-metadata-opa-annotations)
- [Using with Your Pulumi Projects](#using-with-your-pulumi-projects)
- [Testing Your Policies](#testing-your-policies)
- [Policy Pack Structure](#policy-pack-structure)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **Pulumi CLI** (v3.227.0+): [Install Pulumi](https://www.pulumi.com/docs/get-started/install/)
- **OPA CLI** (optional, for testing): [Install OPA](https://www.openpolicyagent.org/docs/latest/#1-download-opa)

The OPA analyzer plugin is installed automatically when you first run a policy pack with `runtime: opa`.

---

## Quick Start

### Step 1: Create a Policy Pack

```bash
mkdir my-policies
cd my-policies
```

Create `PulumiPolicy.yaml`:
```yaml
description: My Security Policies
runtime: opa
# Optional: set inputFormat to "kubernetes-admission" for Gatekeeper-compatible rules.
# See "Kubernetes Admission Controller Compatibility" below.
```

Create `s3-security.rego`:
```rego
package aws

# METADATA
# title: No Public S3 Buckets
# description: S3 buckets must not use public-read ACLs.
# custom:
#   message: Set the ACL to 'private' or remove it entirely.
deny_public_buckets[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not have public-read ACL", [input.__name])
}

# METADATA
# title: Require S3 Encryption
# description: All S3 buckets must have server-side encryption configured.
# custom:
#   message: Add a serverSideEncryptionConfiguration block to the bucket.
deny_encryption[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [input.__name])
}
```

### Step 2: Use with Your Pulumi Project

```bash
# Navigate to your Pulumi project
cd /path/to/your/pulumi/project

# Run preview with policies
pulumi preview --policy-pack /path/to/my-policies

# If policies pass, deploy
pulumi up --policy-pack /path/to/my-policies
```

---

## Policy Examples

### AWS: Prevent Unrestricted Security Groups

```rego
package aws

# METADATA
# title: No SSH from Anywhere
# description: Security groups must not allow SSH (port 22) from 0.0.0.0/0.
# custom:
#   message: Restrict SSH access to specific IP ranges or use a bastion host.
deny_open_ssh[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "tcp"
    rule.fromPort == 22
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows SSH from 0.0.0.0/0", [input.__name])
}

# METADATA
# title: No RDP from Anywhere
# description: Security groups must not allow RDP (port 3389) from 0.0.0.0/0.
# custom:
#   message: Restrict RDP access to specific IP ranges or use a VPN.
deny_open_rdp[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "tcp"
    rule.fromPort == 3389
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows RDP from 0.0.0.0/0", [input.__name])
}
```

### Kubernetes: Enforce Pod Security Standards

```rego
package kubernetes

# METADATA
# title: No Privileged Containers
# description: Deployments must not run containers in privileged mode.
# custom:
#   message: Set securityContext.privileged to false or remove it.
deny_privileged[msg] {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("Deployment '%s' must not run privileged containers", [input.metadata.name])
}

# METADATA
# title: Require CPU Limits
# description: All containers must specify CPU resource limits.
# custom:
#   message: Add resources.limits.cpu to each container spec.
deny_cpu_limits[msg] {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.resources.limits.cpu
    msg := sprintf("Deployment '%s' container '%s' must specify CPU limits",
                   [input.metadata.name, container.name])
}

# METADATA
# title: Require Standard Labels
# description: Deployments must include standard Kubernetes labels.
# custom:
#   message: Add app.kubernetes.io/name and app.kubernetes.io/version labels.
required_labels = [
    "app.kubernetes.io/name",
    "app.kubernetes.io/version"
]

deny_required_labels[msg] {
    input.kind == "Deployment"
    some label in required_labels
    not input.metadata.labels[label]
    msg := sprintf("Deployment '%s' missing required label: %s",
                   [input.metadata.name, label])
}
```

### Azure: Storage Account Security

```rego
package azure

# METADATA
# title: Require HTTPS Traffic
# description: Storage accounts must only accept HTTPS traffic.
# custom:
#   message: Set enableHttpsTrafficOnly to true.
deny_https_only[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.enableHttpsTrafficOnly == false
    msg := sprintf("Storage account '%s' must enable HTTPS-only traffic", [input.__name])
}

# METADATA
# title: Require TLS 1.2
# description: Storage accounts must use TLS 1.2 or higher.
# custom:
#   message: Set minimumTlsVersion to "TLS1_2".
deny_tls_version[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.minimumTlsVersion
    input.minimumTlsVersion != "TLS1_2"
    msg := sprintf("Storage account '%s' must use TLS 1.2 or higher", [input.__name])
}

# METADATA
# title: No Public Blob Access
# description: Storage accounts must not allow public blob access.
# custom:
#   message: Set allowBlobPublicAccess to false.
deny_public_blob_access[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.allowBlobPublicAccess == true
    msg := sprintf("Storage account '%s' must not allow public blob access", [input.__name])
}
```

### Environment-Specific Policies

```rego
package aws

# METADATA
# title: Production RDS Multi-AZ
# description: Production RDS instances must have Multi-AZ enabled for high availability.
# custom:
#   message: Set multiAz to true for production RDS instances.
deny_prod_multi_az[msg] {
    input.type == "aws:rds/instance:Instance"
    contains(lower(input.__name), "prod")
    not input.multiAz
    msg := sprintf("Production RDS '%s' must have Multi-AZ enabled", [input.__name])
}

# METADATA
# title: Production RDS Backup Retention
# description: Production RDS instances must retain backups for at least 7 days.
# custom:
#   message: Set backupRetentionPeriod to 7 or higher.
deny_prod_backup_retention[msg] {
    input.type == "aws:rds/instance:Instance"
    contains(lower(input.__name), "prod")
    input.backupRetentionPeriod < 7
    msg := sprintf("Production RDS '%s' needs 7+ days backup retention", [input.__name])
}
```

---

## Resource Input Structure

When OPA evaluates a policy, the `input` object contains both the resource's own properties and additional metadata about the resource. This gives policies full access to the resource context provided by Pulumi.

### Top-Level Fields

Resource properties are overlaid at the top level for backwards compatibility:

```rego
# Access resource properties directly
input.acl              # e.g. "public-read"
input.bucketName       # e.g. "my-bucket"
```

> **There is no `args.props` here.** Properties live at the **top level** of `input`
> (`input.acl`) and in the **`input.properties`** bag (`input.properties.acl`). The Node.js
> Policy SDK exposes resource inputs as `args.props`, which trips up authors porting rules:
> in OPA there is no `args` object. For convenience `input.props` is accepted as an alias for
> `input.properties`, but prefer `input.<property>` or `input.properties.<property>`. Like any
> top-level field, `input.props`/`input.properties` can be shadowed by a resource property of the
> same name — `input.__props`/`input.__properties` are always collision-safe. A typo'd
> path like `input.args.props.acl` is simply `undefined`, and an undefined reference fails
> silently in either direction: the rule matches **nothing**, or **everything** if the reference
> sits under `not` (e.g. `not input.args.props.acl` is always true).

### Metadata Fields

The following metadata fields are also available at the top level. If a resource property has the same key as a metadata field, the property takes precedence. Use the `__`-prefixed versions for guaranteed access:

| Field | Collision-Safe | Description |
|-------|---------------|-------------|
| `input.type` | `input.__type` | Resource type (e.g. `aws:s3/bucket:Bucket`) |
| `input.urn` | `input.__urn` | Resource URN |
| `input.name` | `input.__name` | Resource logical name |
| `input.options` | `input.__options` | Resource options (see below) |
| `input.provider` | `input.__provider` | Provider information (see below) |
| `input.properties` | `input.__properties` | Nested properties bag |
| `input.props` | `input.__props` | Alias for `input.properties` (see callout above) |

### Resource Options

Access deployment options via `input.options` (or `input.__options`):

```rego
# METADATA
# title: Production Resources Must Be Protected
# description: Production resources must have the protect option enabled.
# custom:
#   message: Set the protect resource option to true.
deny_prod_protect[msg] {
    contains(lower(input.__name), "prod")
    not input.options.protect
    msg := sprintf("Production resource '%s' must have protect enabled", [input.__name])
}
```

Available options fields:
- `protect` - Whether the resource is protected from deletion
- `ignoreChanges` - List of properties to ignore during updates
- `deleteBeforeReplace` - Whether to delete before replacing
- `additionalSecretOutputs` - Additional secret output properties
- `aliasURNs` - Alias URNs for the resource
- `aliases` - Alias definitions (with `urn`, `name`, `type`, `project`, `stack`, `parent`, `noParent`)
- `customTimeouts` - Custom timeouts (`create`, `update`, `delete`)
- `parent` - Parent resource URN

### Provider Information

Access provider details via `input.provider` (or `input.__provider`):

```rego
# METADATA
# title: Avoid Default Provider
# description: Resources should use an explicitly configured provider.
# custom:
#   message: Create a named provider and pass it via the provider resource option.
warn_default_provider[msg] {
    input.provider
    contains(input.provider.name, "default")
    msg := sprintf("Resource '%s' is using the default provider", [input.__name])
}
```

Available provider fields: `type`, `name`, `urn`, `properties`

### Nested Properties Bag

Access properties without metadata collisions via `input.properties` (or `input.__properties`):

```rego
# METADATA
# title: Block Dangerous Type Property
# description: Flags resources whose 'type' property has a dangerous value.
# custom:
#   message: Change the 'type' property to a safe value.
deny_dangerous_type[msg] {
    input.properties.type == "dangerous-value"
    msg := "The 'type' property has a dangerous value"
}
```

---

## Kubernetes Admission Controller Compatibility

If you have existing [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) constraint templates, you can reuse them directly with Pulumi by setting `inputFormat: kubernetes-admission` in `PulumiPolicy.yaml`.

### How It Works

Standard Pulumi OPA policies see resource properties overlaid at the top level of `input`. Gatekeeper rules expect a different structure: `input.review.object.<properties>`. When `inputFormat: kubernetes-admission` is active, the analyzer automatically wraps Kubernetes resources in the Gatekeeper AdmissionReview structure before passing them to OPA:

```
input.review.object     — the full Kubernetes resource (properties + synthesized apiVersion/kind)
input.review.kind       — { group, version, kind }
input.review.name       — resource name (from metadata.name or Pulumi logical name)
input.review.namespace  — namespace (from metadata.namespace, empty if not set)
input.review.operation  — always "CREATE"
input.parameters        — per-rule policy configuration properties
input._pulumi           — escape hatch for Pulumi metadata (type, urn, name, options, provider)
```

Non-Kubernetes resources (e.g. `aws:s3/bucket:Bucket`) are silently skipped when this mode is active, since Gatekeeper rules are meaningless for non-K8s resources.

### Setup

Set `inputFormat` in your `PulumiPolicy.yaml`:

```yaml
description: Kubernetes Gatekeeper Policy Pack
runtime: opa
inputFormat: kubernetes-admission
```

Then drop in your existing Gatekeeper `.rego` files as-is:

```rego
package gatekeeper

import rego.v1

# This rule works identically in Gatekeeper and Pulumi
violation contains {"msg": msg} if {
    not input.review.object.metadata.labels["app"]
    msg := sprintf("%s '%s' is missing required label: app",
        [input.review.kind.kind, input.review.name])
}
```

### Using `input.parameters`

Gatekeeper Constraint parameters map to `input.parameters`. Configure them via the standard Pulumi policy configuration — each rule's `properties` are injected as `input.parameters` before evaluation:

**Policy** (`replica-limits.rego`):
```rego
package gatekeeper

import rego.v1

violation contains {"msg": msg} if {
    input.review.object.spec.replicas > input.parameters.maxReplicas
    msg := sprintf("Deployment '%s' has %d replicas, max allowed is %d",
        [input.review.name, input.review.object.spec.replicas, input.parameters.maxReplicas])
}
```

**Configuration** (passed via Pulumi):
```json
{
    "violation": {
        "properties": {
            "maxReplicas": 5
        }
    }
}
```

This coexists with the standard `data.config.<rule_name>` mechanism — both work simultaneously.

### Accessing Pulumi Metadata

When you need Pulumi-specific information (URN, resource options, provider) from within a Gatekeeper-style rule, use the `input._pulumi` escape hatch:

```rego
violation contains {"msg": msg} if {
    contains(lower(input._pulumi.name), "prod")
    not input._pulumi.options.protect
    msg := sprintf("Production resource '%s' must have protect enabled", [input._pulumi.name])
}
```

### Mixing with Standard Rules

A policy pack uses one input format. If you need both standard Pulumi OPA rules and Gatekeeper-style rules, create separate policy packs — one with `inputFormat: kubernetes-admission` for your Gatekeeper rules, and one without for your standard rules.

### Stack-Level Gatekeeper Rules

Stack-level rules (`stack_deny`, `stack_violation`, `stack_warn`) work with the admission format too. Each resource in `input.resources` is wrapped in the AdmissionReview structure, and non-K8s resources are filtered out:

```rego
package gatekeeper

import rego.v1

stack_violation contains {"msg": msg} if {
    r := input.resources[_]
    not r.review.object.metadata.labels["app"]
    msg := sprintf("%s '%s' is missing required label: app",
        [r.review.kind.kind, r.review.name])
}
```

---

## Stack-Level Policies

Stack-level policies evaluate the entire set of resources in a stack, enabling cross-resource checks like counting resources, verifying relationships, or enforcing fleet-wide standards.

### Writing Stack-Level Rules

Use the `stack_deny`, `stack_violation`, or `stack_warn` prefix. The input contains a `resources` array with all resources in the stack:

```rego
package mypack

# METADATA
# title: S3 Bucket Limit
# description: Stacks must not contain more than 3 S3 buckets.
# custom:
#   message: Remove unused S3 buckets or split into multiple stacks.
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}

# METADATA
# title: Require S3 Encryption (Stack)
# description: All S3 buckets in the stack must have server-side encryption.
# custom:
#   message: Add a serverSideEncryptionConfiguration block to each bucket.
stack_deny_unencrypted_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    not r.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [r.__name])
}

# METADATA
# title: Orphan Security Groups
# description: Warns about security groups not referenced by any other resource.
# custom:
#   message: Remove the unused security group or attach it to a resource.
stack_warn_orphan_security_groups[msg] {
    sg := input.resources[_]
    sg.type == "aws:ec2/securityGroup:SecurityGroup"
    all_deps := {dep | r := input.resources[_]; dep := r.dependencies[_]}
    not all_deps[sg.urn]
    msg := sprintf("Security group '%s' is not referenced by any resource", [sg.__name])
}
```

### Stack Input Structure

Each resource in `input.resources` contains all the same fields as a resource-level input (properties, metadata, options, provider), plus:

- `dependencies` - Array of URNs this resource depends on
- `propertyDependencies` - Map of property names to arrays of dependency URNs

---

## Policy Configuration

Policy configuration allows you to customize policy behavior without modifying Rego code. You can override enforcement levels, disable rules, and inject custom properties.

### Enforcement Level Overrides

Override the default enforcement level for any rule via the Pulumi policy configuration:

```json
{
    "deny_public_buckets": {
        "enforcementLevel": "advisory"
    },
    "warn_logging": {
        "enforcementLevel": "mandatory"
    },
    "deny_old_instance_types": {
        "enforcementLevel": "disabled"
    }
}
```

Valid enforcement levels: `mandatory`, `advisory`, `disabled`.

Use `"all"` to set a pack-wide default:

```json
{
    "all": {
        "enforcementLevel": "advisory"
    },
    "deny_public_buckets": {
        "enforcementLevel": "mandatory"
    }
}
```

### Custom Configuration Properties

Inject custom values into policies via `data.config.<policy_name>.<key>`:

**Policy** (`policies/ec2.rego`):
```rego
package aws

# METADATA
# title: Limit EC2 Instance Size
# description: EC2 instances must not exceed the configured maximum size.
# custom:
#   message: Use an instance type at or below the configured maxInstanceSize.
deny_large_instances[msg] {
    input.type == "aws:ec2/instance:Instance"
    max_size := data.config.deny_large_instances.maxInstanceSize
    instance_sizes := {"t3.micro": 1, "t3.small": 2, "t3.medium": 3, "t3.large": 4, "t3.xlarge": 5}
    instance_sizes[input.instanceType] > instance_sizes[max_size]
    msg := sprintf("Instance '%s' type '%s' exceeds maximum allowed size '%s'",
                   [input.__name, input.instanceType, max_size])
}
```

**Configuration** (passed via Pulumi):
```json
{
    "deny_large_instances": {
        "properties": {
            "maxInstanceSize": "t3.medium"
        }
    }
}
```

### Config Schema

Declare a JSON schema for each rule's configuration properties by adding a `config-schema.json` file alongside your Rego files:

```json
{
    "deny_large_instances": {
        "properties": {
            "maxInstanceSize": {
                "type": "string",
                "default": "t3.large"
            }
        },
        "required": ["maxInstanceSize"]
    }
}
```

Pulumi validates the configuration against this schema before evaluation. If a rule declares a config schema but no configuration is provided, the analyzer emits a warning since rules that reference `data.config` will silently not fire.

---

## Policy Metadata (OPA Annotations)

Use OPA's `# METADATA` annotation blocks to provide rich metadata for your policies. The analyzer extracts `title`, `description`, and `custom.message` from annotations and reports them to Pulumi.

```rego
package aws

# METADATA
# title: S3 Public Access Policy
# scope: package

# METADATA
# title: No Public S3 Buckets
# description: S3 buckets must not use public-read or public-read-write ACLs
# custom:
#   message: Set the ACL to 'private' or remove it entirely
deny_public_buckets[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl in ["public-read", "public-read-write"]
    msg := sprintf("S3 bucket '%s' must not be publicly accessible", [input.__name])
}
```

- **`title`** on a rule sets its `DisplayName`
- **`description`** sets its `Description`
- **`custom.message`** sets its `Message` (remediation guidance)
- **`title`** with `scope: package` sets the policy pack's `DisplayName`

---

## Using with Your Pulumi Projects

### Method 1: Local Policy Pack (Development)

```bash
# During development, reference local policy pack
pulumi preview --policy-pack ./policies
pulumi up --policy-pack ./policies
```

### Method 2: Published Policy Pack (Production)

```bash
# Publish to Pulumi Cloud (one-time)
cd policies
pulumi policy publish

# Enable for your organization in Pulumi Cloud UI
# All projects will automatically enforce these policies
```

### Method 3: CI/CD Integration

**GitHub Actions Example**:
```yaml
name: Pulumi Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Pulumi
        uses: pulumi/actions@v4

      - name: Pulumi Preview with Policies
        run: |
          pulumi preview --policy-pack ./policies
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
```

### Method 4: Pre-commit Hook

Create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
pulumi preview --policy-pack ./policies --non-interactive
exit $?
```

---

## Testing Your Policies

### Unit Testing with OPA

Create test fixtures as JSON and evaluate them with the OPA CLI:

```bash
# test-fixtures/s3-public.json
# { "__name": "test-bucket", "type": "aws:s3/bucket:Bucket", "acl": "public-read" }

opa eval --data policies/ --input test-fixtures/s3-public.json "data.aws.deny"
```

### Integration Testing with Pulumi

```bash
# Run with a real Pulumi program
pulumi preview --policy-pack ./policies
```

---

## Policy Pack Structure

### Recommended Layout

```
my-policies/
├── PulumiPolicy.yaml         # Policy pack metadata
├── config-schema.json        # Optional: config schemas for configurable rules
├── aws/
│   ├── s3.rego              # S3 security policies
│   ├── ec2.rego             # EC2 & security groups
│   ├── rds.rego             # RDS database policies
│   └── iam.rego             # IAM policies
├── azure/
│   ├── storage.rego         # Storage account policies
│   ├── network.rego         # NSG & network policies
│   └── sql.rego             # SQL database policies
├── kubernetes/
│   ├── pod-security.rego    # Pod security standards
│   ├── resources.rego       # Resource requirements
│   └── labels.rego          # Label requirements
└── tests/
    └── fixtures/            # Test data
```

### `PulumiPolicy.yaml` Fields

| Field | Required | Description |
|-------|----------|-------------|
| `description` | No | Human-readable description of the policy pack |
| `runtime` | Yes | Must be `opa` |
| `inputFormat` | No | Set to `kubernetes-admission` for [Gatekeeper-compatible rules](#kubernetes-admission-controller-compatibility) |

### Package Naming

All `.rego` files in a policy pack **must** use the same package name. Subpackages (e.g. `package aws.s3`) are not supported.

### Rule Prefixes and Severity

**The rule name prefix is the API.** A rule is only evaluated if its name matches one of
the recognized prefixes below. Any rule whose name doesn't match is treated as a helper
("library routine") and is **never evaluated** — it will not fire, pass, or fail. There is
no separate annotation or registration step: the prefix alone decides whether a rule runs.

The prefixes are **case-sensitive** and use **underscores** as separators:

**Resource-level rules** (evaluated per-resource via `Analyze`):
- **`deny[msg]`** or **`violation[msg]`** - Mandatory (blocks deployment)
- **`warn[msg]`** - Advisory (shows warning only)

**Stack-level rules** (evaluated once for the entire stack via `AnalyzeStack`):
- **`stack_deny[msg]`** or **`stack_violation[msg]`** - Mandatory (blocks deployment)
- **`stack_warn[msg]`** - Advisory (shows warning only)

Rules can include a suffix for disambiguation (e.g. `deny_public_buckets`, `stack_warn_orphan_sgs`).

> **Common silent failure:** a misnamed rule simply doesn't run — no error, no violation.
> `denyPublicBuckets` (camelCase), `denies_public` (typo), and `Deny_Public` (wrong case)
> are all treated as helpers and skipped. When the analyzer detects a name that *looks* like
> a mistyped rule it prints `warning[opa/unrecognized-rule]` to stderr naming the rule and how
> to fix it; if **no** rule in the pack is recognized it prints `warning[opa/zero-rules]` (the
> pack would enforce nothing). These `warning[opa/...]` codes are stable — grep for them in CI
> to fail a build on misnamed policies. The safest habit is to copy a working prefix exactly.

**Name rules exactly like the left column — anything else is silently skipped:**

| ✅ Evaluated | ❌ Skipped (treated as a helper) | Why it's skipped |
|---|---|---|
| `deny_public_buckets[msg]` | `denyPublicBuckets[msg]` | camelCase instead of `snake_case` |
| `violation_open_ports[msg]` | `Deny_Public[msg]` | wrong case (`Deny`, not `deny`) |
| `warn_missing_tags[msg]` | `denies_public[msg]` | not a recognized keyword |
| `stack_deny_too_many[msg]` | `require_https[msg]`, `must_have_tags[msg]` | correctly spelled, **wrong API** — use `deny`/`warn`, not synonyms like `require`/`must`/`ensure` |

```rego
# METADATA
# title: No Public Access
# description: Resources must not allow public read access.
# custom:
#   message: Remove the public-read ACL.
deny_public_access[msg] {
    input.acl == "public-read"
    msg := "Public access not allowed"
}

# METADATA
# title: Enable Access Logging
# description: Resources should have access logging enabled.
# custom:
#   message: Add a loggings configuration block.
warn_logging[msg] {
    count(object.get(input, "loggings", [])) == 0
    msg := "Consider enabling access logs"
}

# METADATA
# title: S3 Bucket Limit
# description: Stacks must not contain more than 3 S3 buckets.
# custom:
#   message: Remove unused buckets or split into multiple stacks.
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}
```

---

## Best Practices

### 1. Start with Warnings

Begin with `warn[msg]` to understand impact, then upgrade to `deny[msg]` once validated.

### 2. Provide Clear Messages

Include the resource name and specific remediation steps in violation messages. Use `# METADATA` annotations so Pulumi can display policy context in its output.

### 3. Use Helper Functions

Keep policies DRY:

```rego
package kubernetes

# Helper: Check if resource is a workload
is_workload {
    input.kind == "Deployment"
}

is_workload {
    input.kind == "StatefulSet"
}

is_workload {
    input.kind == "DaemonSet"
}

# METADATA
# title: Workload Security Policy
# description: Workloads must meet security requirements.
# custom:
#   message: Review the workload's security configuration.
# Use helper in policies
deny_workload_security[msg] {
    is_workload
    # policy logic
}
```

### 4. Test Both Ways

Always create fixtures for both valid (should pass) and invalid (should fail) configurations.

### 5. Know the Rego Idioms That Bite

A handful of Rego idioms look correct but silently make a rule fire on 0% or 100% of
resources. These are the most common ways a policy "passes" without ever doing anything:

| Goal | ✅ Do this | ❌ Not this | Why the wrong form fails silently |
|------|-----------|------------|-----------------------------------|
| "collection is empty or missing" | `count(object.get(input, "tags", [])) == 0` | `not input.tags` or `count(input.tags) == 0` | `not input.tags` matches only a **missing** key (an empty `[]`/`{}` is still "defined"); `count(input.tags) == 0` matches only a **present-but-empty** value — it's `undefined` (so never matches) when the key is missing. `object.get(..., [])` supplies a default, covering both. |
| "key exists" | `input.encryption` | `input.encryption == true` | A non-boolean (e.g. a config block) is truthy in `input.encryption` but `!= true`, so the equality form fires on 0%. |
| "no element matches" | `count([x | x := input.rules[_]; bad(x)]) == 0` | `not input.rules[_]` | `not input.rules[_]` negates over the whole collection and rarely means what you expect. |
| read a property | `input.acl` or `input.properties.acl` | `input.args.props.acl` | There is no `args` object (that's the Node SDK). The path is `undefined`, so the rule fires on 0% of resources — or 100% if the reference is under `not`. |

When in doubt, run `opa eval` against a fixture you *know* should violate and confirm you
get a result — a rule that returns nothing on a known-bad input is the tell-tale sign of one
of the idioms above. See [Testing Your Policies](#testing-your-policies).

---

## Troubleshooting

### Policies not being evaluated

1. Verify all `.rego` files use the same package name (no subpackages like `aws.s3`)
2. Verify `PulumiPolicy.yaml` specifies `runtime: opa`
3. Check the policy pack path is correct

### Violations not shown

1. Rule must use a recognized prefix: `deny`, `violation`, `warn`, `stack_deny`, `stack_violation`, or `stack_warn`. Prefixes are **case-sensitive** and use **underscores** (`deny_public`, not `denyPublic` or `Deny_Public`). A misnamed rule is silently treated as a helper and never runs — watch stderr for `warning[opa/unrecognized-rule]` (a single misnamed rule) or `warning[opa/zero-rules]` (the whole pack evaluates nothing). See [Rule Prefixes and Severity](#rule-prefixes-and-severity) for the ✅/❌ naming table.
2. Check your Rego idioms — for "empty or missing", neither `not input.tags` (matches only a missing key) nor `count(input.tags) == 0` (`undefined`, so never matches, when the key is missing) is enough; use `count(object.get(input, "tags", [])) == 0`. See [Best Practices → Know the Rego Idioms That Bite](#5-know-the-rego-idioms-that-bite).
3. Verify the input structure matches your resource type (properties are at the top level or under `input.properties`, never under `input.args`).
4. Use `pulumi preview --policy-pack ./policies --debug` for verbose output

### Gatekeeper rules not firing

1. Verify `PulumiPolicy.yaml` includes `inputFormat: kubernetes-admission`
2. Ensure the resource type starts with `kubernetes:` — non-K8s resources are skipped in admission mode
3. Check that rules use `input.review.object.*` (not `input.*` directly)
4. If using `input.parameters`, verify the rule name matches the config key and `properties` is non-empty

### Policy passes but shouldn't

Add a temporary advisory rule to inspect the input — the `warn_` prefix makes it actually
evaluate, and `__type`/`__name` are collision-safe:

```rego
warn_debug_input[msg] {
    msg := sprintf("Type: %s, Name: %s", [input.__type, input.__name])
}
```

---

## Examples and Resources

Ready-to-use policy packs in `examples/`:

- **`examples/policy-aws/`** - AWS security policies with configuration, stack-level rules, and OPA annotations
- **`examples/policy-kubernetes/`** - Kubernetes label and image policies with resource metadata access
- **`examples/policy-kubernetes-gatekeeper/`** - Reuse OPA Gatekeeper constraint templates with `inputFormat: kubernetes-admission`

Test policies in `tests/` covering AWS, Azure, Kubernetes, Kubernetes Admission Controller, stack-level, and metadata scenarios. See the [Test Corpus Documentation](tests/README.md) for a complete catalog.

### External Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Pulumi CrossGuard](https://www.pulumi.com/docs/guides/crossguard/)
- [Rego Playground](https://play.openpolicyagent.org/) - Test policies online

---

## Contributing

Contributions welcome! Please add tests for new policies, follow existing code style, and update the test corpus.

## License

Apache License 2.0
