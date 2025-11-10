# OPA Policy Test Corpus

This directory contains a comprehensive test corpus for OPA policies targeting AWS, Azure Native, and Kubernetes resources.

## Directory Structure

```
tests/
├── aws/
│   ├── PulumiPolicy.yaml           # AWS policy pack configuration
│   ├── policies/                    # OPA policy files (.rego)
│   │   ├── s3_security.rego
│   │   ├── ec2_security.rego
│   │   ├── iam_security.rego
│   │   └── rds_security.rego
│   └── fixtures/                    # Test data (valid/invalid resources)
│       ├── s3_valid.json
│       ├── s3_invalid_*.json
│       └── ...
├── azure/
│   ├── PulumiPolicy.yaml           # Azure policy pack configuration
│   ├── policies/
│   │   ├── storage_security.rego
│   │   ├── compute_security.rego
│   │   ├── network_security.rego
│   │   └── sql_security.rego
│   └── fixtures/
│       └── ...
└── kubernetes/
    ├── PulumiPolicy.yaml           # Kubernetes policy pack configuration
    ├── policies/
    │   ├── pod_security.rego
    │   ├── resource_requirements.rego
    │   ├── labels_annotations.rego
    │   ├── service_security.rego
    │   └── image_security.rego
    └── fixtures/
        └── ...
```

## Policy Categories

### AWS Policies

1. **S3 Security** (`s3_security.rego`)
   - Deny public bucket access
   - Require encryption
   - Require versioning for production
   - Require access logging
   - Block public access settings

2. **EC2 Security** (`ec2_security.rego`)
   - Require EBS volume encryption
   - Instance type restrictions for production
   - Security group rules (no unrestricted SSH/RDP)
   - Monitoring requirements

3. **IAM Security** (`iam_security.rego`)
   - No wildcard permissions
   - MFA requirements for assume role
   - Prefer roles over users

4. **RDS Security** (`rds_security.rego`)
   - Storage encryption required
   - No publicly accessible databases
   - Automated backups required
   - Multi-AZ for production
   - Deletion protection

### Azure Native Policies

1. **Storage Security** (`storage_security.rego`)
   - HTTPS-only traffic
   - Minimum TLS version (1.2+)
   - Disable public blob access
   - Encryption requirements

2. **Compute Security** (`compute_security.rego`)
   - Managed disks required
   - Disk encryption
   - No public IPs for production VMs

3. **Network Security** (`network_security.rego`)
   - NSG rules (no unrestricted SSH/RDP)
   - DDoS protection for production
   - Application Gateway WAF

4. **SQL Security** (`sql_security.rego`)
   - Azure AD authentication
   - Transparent Data Encryption
   - Auditing and threat protection
   - Geo-redundant backups for production

### Kubernetes Policies

1. **Pod Security** (`pod_security.rego`)
   - No privileged containers
   - Drop all capabilities
   - Run as non-root
   - Read-only root filesystem
   - No host namespaces

2. **Resource Requirements** (`resource_requirements.rego`)
   - CPU and memory limits required
   - CPU and memory requests recommended
   - Requests must not exceed limits

3. **Labels & Annotations** (`labels_annotations.rego`)
   - Standard Kubernetes labels
   - Environment labels
   - Owner annotations for production

4. **Service Security** (`service_security.rego`)
   - Internal LoadBalancers for production
   - Avoid NodePort
   - TLS required for production Ingress

5. **Image Security** (`image_security.rego`)
   - No :latest tags
   - Approved registries only
   - Image pull policy specification

## Testing with OPA CLI

You can test these policies directly using the OPA CLI:

### Install OPA

```bash
# macOS
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Verify installation
opa version
```

### Test AWS Policies

```bash
# Navigate to AWS test directory
cd tests/aws

# Test S3 policy against valid fixture
opa eval --data policies/s3_security.rego --input fixtures/s3_valid.json "data.aws.deny"
# Expected: [] (no violations)

# Test S3 policy against invalid fixture
opa eval --data policies/s3_security.rego --input fixtures/s3_invalid_public.json "data.aws.deny"
# Expected: [violation messages]

# Test all policies in the pack
opa eval --bundle policies/ --input fixtures/s3_valid.json "data.aws"
```

### Test Azure Policies

```bash
cd tests/azure

# Test storage policy
opa eval --data policies/storage_security.rego --input fixtures/storage_valid.json "data.azure.deny"

# Test with invalid TLS version
opa eval --data policies/storage_security.rego --input fixtures/storage_invalid_tls.json "data.azure.deny"
```

### Test Kubernetes Policies

```bash
cd tests/kubernetes

# Test pod security policy
opa eval --data policies/pod_security.rego --input fixtures/deployment_valid.json "data.kubernetes.deny"

# Test privileged container (should fail)
opa eval --data policies/pod_security.rego --input fixtures/deployment_invalid_privileged.json "data.kubernetes.deny"

# Test resource requirements
opa eval --data policies/resource_requirements.rego --input fixtures/deployment_invalid_no_resources.json "data.kubernetes.deny"
```

## Testing with Pulumi

### Option 1: Local Testing with Pulumi CLI

```bash
# Use the policy pack with a Pulumi program
pulumi preview --policy-pack tests/aws
pulumi preview --policy-pack tests/azure
pulumi preview --policy-pack tests/kubernetes
```

### Option 2: Using the Analyzer Plugin

```bash
# Build the analyzer
go build -o pulumi-analyzer-policy-opa ./cmd/pulumi-analyzer-policy-opa

# Run with test fixtures (requires integration with Pulumi engine)
./pulumi-analyzer-policy-opa tests/aws
```

## Writing New Tests

### Adding a New Policy

1. Create a new `.rego` file in the appropriate `policies/` directory
2. Follow the package naming convention (`package aws`, `package azure`, or `package kubernetes`)
3. Use `deny[msg]` for mandatory violations
4. Use `warn[msg]` for advisory warnings

Example:

```rego
package aws

import future.keywords.if
import future.keywords.in

# Description of the policy
deny[msg] {
    input.type == "aws:service/resource:Type"
    # condition
    msg := sprintf("Resource '%s' violates policy", [input.__name])
}
```

### Adding Test Fixtures

Create JSON files in the `fixtures/` directory:

- `*_valid.json` - Resources that should pass all policies
- `*_invalid_*.json` - Resources that should fail specific policies

Structure:
```json
{
  "__name": "resource-name",
  "type": "provider:service/resource:Type",
  "property1": "value1",
  "property2": "value2"
}
```

## Running Automated Tests

### Bash Test Runner

```bash
./tests/run_tests.sh
```

### Go Test Runner

```bash
go test ./tests/...
```

## Policy Severity Levels

- **`deny[msg]`** - Mandatory policies that will block resource creation
- **`warn[msg]`** - Advisory policies that will show warnings but allow creation

## Common Patterns

### Checking for Missing Properties

```rego
deny[msg] {
    not input.property
    msg := "Property is required"
}
```

### Checking for Boolean False

```rego
deny[msg] {
    input.property == false
    msg := "Property must be enabled"
}
```

### Environment-Specific Rules

```rego
deny[msg] {
    contains(lower(input.__name), "prod")
    # production-specific rule
    msg := "Production resource must meet stricter requirements"
}
```

### Array Iteration

```rego
deny[msg] {
    some item in input.items
    # check item
    msg := sprintf("Item %v violates policy", [item])
}
```

## References

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Pulumi CrossGuard](https://www.pulumi.com/docs/guides/crossguard/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
