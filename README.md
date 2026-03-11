# Pulumi OPA Policy Bridge

> Write infrastructure policies in [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and enforce them during Pulumi deployments

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Go Version](https://img.shields.io/badge/go-1.24+-blue)]()
[![OPA Version](https://img.shields.io/badge/opa-1.10+-blue)]()
[![Pulumi SDK](https://img.shields.io/badge/pulumi-v3.206-purple)]()

## Why Use OPA with Pulumi?

**Policy as Code** for your infrastructure deployments. Define security, compliance, and best practice policies in Rego and enforce them **before** resources are deployed.

### Key Benefits

✅ **Prevent Security Issues** - Block insecure configurations before they reach production
✅ **Enforce Compliance** - Ensure SOC2, HIPAA, PCI-DSS standards automatically
✅ **Shift Left** - Catch policy violations during preview, not after deployment
✅ **Use Familiar Tools** - Leverage OPA's powerful Rego language
✅ **Cross-Cloud** - Same policy framework for AWS, Azure, GCP, Kubernetes

## Quick Example

**Policy** (prevents public S3 buckets):
```rego
package aws

deny[msg] {
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
#   [mandatory] aws.deny
#   S3 bucket 'my-bucket' must not be publicly accessible
```

**Result**: Deployment is blocked until the violation is fixed! 🛡️

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Policy Examples](#policy-examples)
- [Resource Input Structure](#resource-input-structure)
- [Stack-Level Policies](#stack-level-policies)
- [Policy Configuration](#policy-configuration)
- [Policy Metadata (OPA Annotations)](#policy-metadata-opa-annotations)
- [Using with Your Pulumi Projects](#using-with-your-pulumi-projects)
- [Testing Your Policies](#testing-your-policies)
- [Policy Pack Structure](#policy-pack-structure)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Complete Examples](#complete-examples)

---

## Installation

### Prerequisites

- **Pulumi CLI** (v3.0+): [Install Pulumi](https://www.pulumi.com/docs/get-started/install/)
- **OPA CLI** (optional, for testing): [Install OPA](https://www.openpolicyagent.org/docs/latest/#1-download-opa)

Install the analyzer:

```bash
pulumi plugin install analyzer policy-opa
```

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
```

Create `s3-security.rego`:
```rego
package aws

# Deny public S3 buckets
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not have public-read ACL", [input.__name])
}

# Require encryption
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [input.__name])
}
```

### Step 2: Test Your Policies

Use the included test corpus to verify your setup:

```bash
# Quick test with OPA CLI
cd ../tests
./run_tests.sh

# Or test with real Pulumi programs
cd integration
./run_integration_tests.sh
```

### Step 3: Use with Your Pulumi Project

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

# No SSH from anywhere
deny[msg] {
    input.type == "aws:ec2/securityGroup:SecurityGroup"
    some rule in input.ingress
    rule.protocol == "tcp"
    rule.fromPort == 22
    some cidr in rule.cidrBlocks
    cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%s' allows SSH from 0.0.0.0/0", [input.__name])
}

# No RDP from anywhere
deny[msg] {
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

# No privileged containers
deny[msg] {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("Deployment '%s' must not run privileged containers", [input.metadata.name])
}

# Require resource limits
deny[msg] {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.resources.limits.cpu
    msg := sprintf("Deployment '%s' container '%s' must specify CPU limits",
                   [input.metadata.name, container.name])
}

# Require standard labels
required_labels = [
    "app.kubernetes.io/name",
    "app.kubernetes.io/version"
]

deny[msg] {
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

# Require HTTPS-only traffic
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.enableHttpsTrafficOnly == false
    msg := sprintf("Storage account '%s' must enable HTTPS-only traffic", [input.__name])
}

# Require minimum TLS 1.2
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.minimumTlsVersion
    input.minimumTlsVersion != "TLS1_2"
    msg := sprintf("Storage account '%s' must use TLS 1.2 or higher", [input.__name])
}

# Disable public blob access
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.allowBlobPublicAccess == true
    msg := sprintf("Storage account '%s' must not allow public blob access", [input.__name])
}
```

### Environment-Specific Policies

```rego
package aws

# Stricter rules for production
deny[msg] {
    input.type == "aws:rds/instance:Instance"
    contains(lower(input.__name), "prod")
    not input.multiAz
    msg := sprintf("Production RDS '%s' must have Multi-AZ enabled", [input.__name])
}

deny[msg] {
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

### Resource Options

Access deployment options via `input.options` (or `input.__options`):

```rego
# Require protection on production resources
deny[msg] {
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
# Warn if using default provider
warn[msg] {
    input.provider
    contains(input.provider.name, "default")
    msg := sprintf("Resource '%s' is using the default provider", [input.__name])
}
```

Available provider fields: `type`, `name`, `urn`, `properties`

### Nested Properties Bag

Access properties without metadata collisions via `input.properties` (or `input.__properties`):

```rego
# Access a property that might collide with a metadata field name
deny[msg] {
    input.properties.type == "dangerous-value"
    msg := "The 'type' property has a dangerous value"
}
```

---

## Stack-Level Policies

Stack-level policies evaluate the entire set of resources in a stack, enabling cross-resource checks like counting resources, verifying relationships, or enforcing fleet-wide standards.

### Writing Stack-Level Rules

Use the `stack_deny` or `stack_warn` prefix. The input contains a `resources` array with all resources in the stack:

```rego
package mypack

# Limit the number of S3 buckets per stack
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}

# All S3 buckets must have encryption
stack_deny_unencrypted_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    not r.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [r.__name])
}

# Warn about security groups not referenced by any resource
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

```bash
# Test a single policy
opa eval --data policies/s3.rego \
         --input test-fixtures/s3-public.json \
         "data.aws.deny"

# Expected output: violations array
[
  "S3 bucket 'my-bucket' must not have public-read ACL"
]
```

### Integration Testing with Pulumi

Use the included test suite:

```bash
# Test all AWS policies
cd tests
./run_tests.sh

# Test with real Pulumi programs
cd integration
./run_integration_tests.sh
```

### Writing Your Own Tests

Create test fixtures as JSON:

**`test-fixtures/invalid-s3.json`**:
```json
{
  "__name": "test-bucket",
  "type": "aws:s3/bucket:Bucket",
  "acl": "public-read"
}
```

Test it:
```bash
opa eval --data policies/ --input test-fixtures/invalid-s3.json "data.aws.deny"
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

### Package Naming

All policy files **must** use the same package name:

```rego
# ✅ Correct - all files use "aws"
package aws

# ❌ Wrong - mixing package names
package aws.s3  # This won't work
```

### Rule Prefixes and Severity

Rules are identified by their name prefix, which determines the enforcement level and scope:

**Resource-level rules** (evaluated per-resource via `Analyze`):
- **`deny[msg]`** or **`violation[msg]`** - Mandatory (blocks deployment)
- **`warn[msg]`** - Advisory (shows warning only)

**Stack-level rules** (evaluated once for the entire stack via `AnalyzeStack`):
- **`stack_deny[msg]`** or **`stack_violation[msg]`** - Mandatory (blocks deployment)
- **`stack_warn[msg]`** - Advisory (shows warning only)

Rules can include a suffix for disambiguation (e.g. `deny_public_buckets`, `stack_warn_orphan_sgs`).

```rego
# Critical security issue - block deployment
deny[msg] {
    input.acl == "public-read"
    msg := "Public access not allowed"
}

# Best practice - show warning
warn[msg] {
    not input.loggings
    msg := "Consider enabling access logs"
}

# Stack-level: enforce cross-resource constraints
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}
```

---

## Best Practices

### 1. Start with Warnings

Begin with `warn[msg]` to understand impact, then upgrade to `deny[msg]`:

```rego
# Phase 1: Understand usage
warn[msg] {
    input.type == "aws:ec2/instance:Instance"
    input.instanceType == "t2.micro"
    msg := "Consider using t3.micro for better performance"
}

# Phase 2: After validation, enforce
deny[msg] {
    input.type == "aws:ec2/instance:Instance"
    contains(lower(input.__name), "prod")
    input.instanceType == "t2.micro"
    msg := "Production instances must not use t2.micro"
}
```

### 2. Provide Clear Messages

Include resource name and specific remediation:

```rego
# ❌ Bad - vague message
deny[msg] {
    not input.encrypted
    msg := "Must be encrypted"
}

# ✅ Good - clear and actionable
deny[msg] {
    input.type == "aws:rds/instance:Instance"
    not input.storageEncrypted
    msg := sprintf("RDS instance '%s' must enable storage encryption. Add: storageEncrypted: true",
                   [input.__name])
}
```

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

# Use helper in policies
deny[msg] {
    is_workload
    # policy logic
}
```

### 4. Test Both Ways

Always create fixtures for:
- ✅ Valid configuration (should pass)
- ❌ Invalid configuration (should fail)

### 5. Document Your Policies with OPA Annotations

Use `# METADATA` blocks so Pulumi can display rich policy information:

```rego
# METADATA
# title: Require RDS Encryption
# description: All RDS instances must be encrypted at rest (SOC2 requirement)
# custom:
#   message: Add storageEncrypted: true to the RDS instance
deny_rds_encryption[msg] {
    input.type == "aws:rds/instance:Instance"
    not input.storageEncrypted
    msg := sprintf("RDS instance '%s' must have storage encryption enabled (SOC2)",
                   [input.__name])
}
```

---

## Troubleshooting

### Issue: Policies not being evaluated

**Check:**
1. Package name matches in all `.rego` files
2. `PulumiPolicy.yaml` specifies `runtime: opa`
3. Policy pack path is correct

```bash
# Debug: View what OPA sees
opa eval --data policies/ --format pretty "data"
```

### Issue: Violations not shown

**Check:**
1. Rule uses a recognized prefix: `deny`, `violation`, `warn`, `stack_deny`, `stack_violation`, or `stack_warn`
2. Input structure matches your resource type
3. Use `pulumi preview --policy-pack ./policies --debug` for verbose output

### Issue: "Module not found" error

**Cause:** Package name mismatch

```rego
# All files must use the same package
package aws  # ✅ Use this in ALL files

# Don't mix these:
package aws.s3      # ❌
package aws_policy  # ❌
```

### Issue: Policy passes but shouldn't

**Debug the input:**

```bash
# Add debug rule to see what OPA receives
debug_input[msg] {
    msg := sprintf("Type: %s, Name: %s, Properties: %v",
                   [input.type, input.__name, input])
}
```

---

## Complete Examples

### Example 1: Comprehensive S3 Security

**`policies/PulumiPolicy.yaml`**:
```yaml
description: S3 Security Policy Pack
runtime: opa
```

**`policies/s3.rego`**:
```rego
package aws

import future.keywords.if
import future.keywords.in

# No public buckets
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl in ["public-read", "public-read-write"]
    msg := sprintf("S3 bucket '%s' must not be publicly accessible", [input.__name])
}

# Require encryption
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [input.__name])
}

# Production buckets need versioning
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    contains(lower(input.__name), "prod")
    not input.versioning
    msg := sprintf("Production S3 bucket '%s' must have versioning enabled", [input.__name])
}

deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    contains(lower(input.__name), "prod")
    input.versioning.enabled == false
    msg := sprintf("Production S3 bucket '%s' must have versioning enabled", [input.__name])
}

# Recommend logging
warn[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.loggings
    msg := sprintf("S3 bucket '%s' should enable access logging", [input.__name])
}
```

**Test it:**
```bash
pulumi preview --policy-pack ./policies
```

### Example 2: Kubernetes Security Standards

**`policies/kubernetes.rego`**:
```rego
package kubernetes

import future.keywords.if
import future.keywords.in

# Pod Security: No privileged containers
deny[msg] {
    is_workload
    some container in containers
    container.securityContext.privileged == true
    msg := sprintf("%s '%s' must not run privileged containers",
                   [input.kind, input.metadata.name])
}

# Pod Security: Drop all capabilities
deny[msg] {
    is_workload
    some container in containers
    not container.securityContext.capabilities.drop
    msg := sprintf("%s '%s' must drop all capabilities",
                   [input.kind, input.metadata.name])
}

deny[msg] {
    is_workload
    some container in containers
    container.securityContext.capabilities.drop
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("%s '%s' must drop ALL capabilities",
                   [input.kind, input.metadata.name])
}

# Require resource limits
deny[msg] {
    is_workload
    some container in containers
    not container.resources.limits.cpu
    msg := sprintf("%s '%s' container '%s' must specify CPU limits",
                   [input.kind, input.metadata.name, container.name])
}

deny[msg] {
    is_workload
    some container in containers
    not container.resources.limits.memory
    msg := sprintf("%s '%s' container '%s' must specify memory limits",
                   [input.kind, input.metadata.name, container.name])
}

# Helpers
is_workload if { input.kind == "Deployment" }
is_workload if { input.kind == "StatefulSet" }
is_workload if { input.kind == "DaemonSet" }

containers = input.spec.template.spec.containers {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
}
```

---

## Additional Resources

### Example Policy Packs

Ready-to-use examples in `examples/`:

- **`examples/policy-kubernetes/`** - Kubernetes label and image policies with resource metadata access
- **`examples/policy-aws/`** - AWS security policies with configuration, stack-level rules, and OPA annotations

### Pre-built Test Policies

This repository includes comprehensive test policies in `tests/`:

- **`tests/aws/`** - AWS security policies (S3, EC2, RDS, IAM)
- **`tests/azure/`** - Azure Native policies (Storage, Compute, Network, SQL)
- **`tests/kubernetes/`** - Kubernetes security standards
- **`tests/stack/`** - Stack-level cross-resource policies
- **`tests/metadata/`** - Policies using resource metadata, options, and provider info

Copy and customize for your needs!

### Documentation

- 📚 [Test Corpus Documentation](tests/README.md) - Complete policy catalog
- 🚀 [Getting Started Guide](tests/GETTING_STARTED.md) - 5-minute quick start
- 📖 [Test Index](tests/TEST_INDEX.md) - All 75+ policies documented
- 📊 [Test Summary](tests/SUMMARY.md) - Coverage overview

### External Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Pulumi CrossGuard](https://www.pulumi.com/docs/guides/crossguard/)
- [Rego Playground](https://play.openpolicyagent.org/) - Test policies online

---

## Contributing

Contributions welcome! Please:

1. Add tests for new policies
2. Follow existing code style
3. Document your policies
4. Update the test corpus

---

## Support

- 🐛 [Report Issues](https://github.com/pulumi/pulumi-policy-opa/issues)
- 💬 [Discussions](https://github.com/pulumi/pulumi-policy-opa/discussions)
- 📧 [Pulumi Community Slack](https://slack.pulumi.com)

---

## License

Apache License 2.0

---

**Built with ❤️ by the Pulumi community**

Start securing your infrastructure deployments today! 🚀
