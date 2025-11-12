# OPA Policy Test Corpus Index

Complete index of all test cases, policies, and fixtures in this test corpus.

## Quick Start

```bash
# Run unit tests with OPA CLI
cd tests
./run_tests.sh

# Run integration tests with Pulumi
cd tests/integration
./run_integration_tests.sh

# Run Go tests
go test ./tests/... -v
```

## Test Coverage Summary

| Provider   | Policies | Valid Fixtures | Invalid Fixtures | Integration Tests |
|------------|----------|----------------|------------------|-------------------|
| AWS        | 4        | 4              | 5                | 2                 |
| Azure      | 4        | 2              | 2                | 0                 |
| Kubernetes | 5        | 3              | 3                | 2                 |
| **Total**  | **13**   | **9**          | **10**           | **4**             |

## AWS Test Cases

### Policies (tests/aws/policies/)

#### s3_security.rego
- **deny**: S3 bucket must not have public-read ACL
- **deny**: S3 bucket must not have public-read-write ACL
- **deny**: S3 bucket must have server-side encryption
- **deny**: Production buckets must have versioning enabled
- **warn**: S3 bucket should have access logging
- **deny**: Bucket public access block must block public ACLs

#### ec2_security.rego
- **deny**: EBS volumes must be encrypted
- **deny**: Production EC2 instances cannot use t2.micro
- **warn**: EC2 instances should have detailed monitoring
- **deny**: Security groups must not allow unrestricted SSH (0.0.0.0/0:22)
- **deny**: Security groups must not allow unrestricted RDP (0.0.0.0/0:3389)
- **warn**: Security groups should not be overly permissive

#### iam_security.rego
- **deny**: IAM policies must not grant wildcard (*) permissions
- **deny**: IAM policies must not grant all resources (*) for write actions
- **warn**: IAM roles should require MFA for assume role
- **warn**: Consider using IAM roles instead of users

#### rds_security.rego
- **deny**: RDS instances must have storage encryption
- **deny**: RDS instances must not be publicly accessible
- **deny**: RDS instances must have automated backups (retention > 0)
- **deny**: Production RDS instances need 7+ days backup retention
- **deny**: Production RDS instances must have Multi-AZ enabled
- **warn**: Production RDS instances should have deletion protection

### Test Fixtures (tests/aws/fixtures/)

**Valid** (Should Pass):
- `s3_valid.json` - Secure S3 bucket with encryption, versioning, logging
- `ec2_valid.json` - Production EC2 with appropriate instance type and monitoring
- `sg_valid.json` - Security group with restricted SSH access
- `rds_valid.json` - Production RDS with encryption, Multi-AZ, backups

**Invalid** (Should Fail):
- `s3_invalid_public.json` - Public-read ACL ❌
- `s3_invalid_no_encryption.json` - No encryption ❌
- `ec2_invalid_instance_type.json` - Production using t2.micro ❌
- `sg_invalid_ssh.json` - Unrestricted SSH from 0.0.0.0/0 ❌
- `rds_invalid_public.json` - Publicly accessible database ❌

### Integration Tests (tests/integration/aws/)

1. **s3-secure/** - Secure S3 bucket configuration ✅
2. **s3-insecure/** - Insecure S3 bucket (public-read, no encryption) ❌

## Azure Native Test Cases

### Policies (tests/azure/policies/)

#### storage_security.rego
- **deny**: Storage accounts must enable HTTPS-only traffic
- **deny**: Storage accounts must use TLS 1.2 or higher
- **deny**: Storage accounts must not allow public blob access
- **warn**: Storage accounts should have encryption enabled
- **warn**: Storage accounts should enable infrastructure encryption
- **deny**: Blob containers must not allow public access

#### compute_security.rego
- **deny**: Virtual machines must use managed disks
- **warn**: VMs should have OS disk encryption
- **deny**: Production VMs should not have public IP addresses
- **deny**: Disks must have encryption enabled
- **deny**: Production disks should use customer-managed keys
- **warn**: VM scale sets should enable automatic OS upgrades
- **warn**: VM scale sets should have health monitoring

#### network_security.rego
- **deny**: NSGs must not allow unrestricted SSH (port 22)
- **deny**: NSGs must not allow unrestricted RDP (port 3389)
- **warn**: NSGs should not be overly permissive
- **deny**: Production virtual networks must have DDoS protection
- **warn**: Application Gateways should have WAF enabled
- **warn**: WAF should be in Prevention mode, not Detection

#### sql_security.rego
- **warn**: SQL Servers should configure Azure AD authentication
- **deny**: SQL Databases must have Transparent Data Encryption
- **warn**: SQL Servers should have auditing enabled
- **warn**: SQL Servers should have Advanced Threat Protection
- **deny**: Production SQL Servers should not allow public network access
- **deny**: Production SQL Databases must use geo-redundant backup

### Test Fixtures (tests/azure/fixtures/)

**Valid**:
- `storage_valid.json` - Storage account with HTTPS, TLS 1.2, no public access
- `vm_valid.json` - VM with managed disk and encryption
- `nsg_valid.json` - NSG with restricted SSH access

**Invalid**:
- `storage_invalid_tls.json` - Using TLS 1.0 ❌
- `nsg_invalid_ssh.json` - Unrestricted SSH from Internet ❌

## Kubernetes Test Cases

### Policies (tests/kubernetes/policies/)

#### pod_security.rego
- **deny**: Containers must not run privileged
- **deny**: Containers must drop ALL capabilities
- **deny**: Containers must not run as root
- **deny**: Containers must have read-only root filesystem
- **warn**: Pods should not use host network
- **warn**: Pods should not use host PID namespace
- **warn**: Pods should not use host IPC namespace

#### resource_requirements.rego
- **deny**: Containers must specify CPU limits
- **deny**: Containers must specify memory limits
- **warn**: Containers should specify CPU requests
- **warn**: Containers should specify memory requests
- **deny**: Requests must not exceed limits

#### labels_annotations.rego
- **deny**: Deployments must include Kubernetes recommended labels:
  - `app.kubernetes.io/name`
  - `app.kubernetes.io/instance`
  - `app.kubernetes.io/version`
  - `app.kubernetes.io/component`
  - `app.kubernetes.io/part-of`
  - `app.kubernetes.io/managed-by`
- **deny**: Services must include Kubernetes recommended labels
- **deny**: Deployments must have 'environment' label
- **warn**: Production resources should have 'owner' annotation
- **warn**: Deployments should have 'description' annotation

#### service_security.rego
- **warn**: Production LoadBalancers should be internal
- **warn**: NodePort should be avoided
- **deny**: Production Ingress must have TLS configured

#### image_security.rego
- **deny**: Containers must not use :latest tag
- **deny**: Containers must specify an image tag
- **warn**: Images should be from approved registries
- **warn**: Containers should specify imagePullPolicy
- **warn**: Production containers should use imagePullPolicy: Always

### Test Fixtures (tests/kubernetes/fixtures/)

**Valid**:
- `deployment_valid.json` - Secure deployment with all labels, resources, security context
- `service_valid.json` - Service with required labels
- `ingress_valid.json` - Production ingress with TLS

**Invalid**:
- `deployment_invalid_privileged.json` - Privileged container ❌
- `deployment_invalid_no_resources.json` - Missing resource limits ❌
- `ingress_invalid_no_tls.json` - Production ingress without TLS ❌

### Integration Tests (tests/integration/kubernetes/)

1. **secure-deployment/** - Deployment with all security best practices ✅
2. **insecure-deployment/** - Privileged container, :latest tag, no resources ❌

## Test Execution Methods

### Method 1: OPA CLI (Unit Tests)

Tests policies in isolation using OPA's evaluation engine.

```bash
cd tests
./run_tests.sh
```

**Pros:**
- Fast execution
- No dependencies on Pulumi
- Direct policy testing

**Cons:**
- Doesn't test full integration
- Requires OPA CLI installation

### Method 2: Pulumi Integration (E2E Tests)

Tests policies through actual Pulumi preview with the OPA analyzer.

```bash
cd tests/integration
./run_integration_tests.sh
```

**Pros:**
- End-to-end testing
- Tests actual analyzer behavior
- Validates Pulumi integration

**Cons:**
- Slower execution
- Requires Pulumi CLI and Node.js
- Must build analyzer first

### Method 3: Go Tests

Programmatic tests using Go testing framework.

```bash
go test ./tests/... -v
```

**Pros:**
- Integrates with Go tooling
- Can run in CI/CD
- Generates coverage reports

**Cons:**
- Requires Go environment
- More complex setup

## Adding New Tests

### 1. Add a New Policy Rule

```bash
# Edit or create a new .rego file
vim tests/aws/policies/new_service.rego
```

```rego
package aws

import future.keywords.if

deny[msg] {
    input.type == "aws:service:Resource"
    not input.requiredProperty
    msg := sprintf("Resource '%s' must have required property", [input.__name])
}
```

### 2. Add Test Fixtures

```bash
# Create valid and invalid fixtures
vim tests/aws/fixtures/new_service_valid.json
vim tests/aws/fixtures/new_service_invalid.json
```

### 3. Add Integration Test (Optional)

```bash
# Create Pulumi program
mkdir tests/integration/aws/new-service
vim tests/integration/aws/new-service/index.ts
```

### 4. Run Tests

```bash
# Verify with OPA
opa eval --data tests/aws/policies/new_service.rego \
         --input tests/aws/fixtures/new_service_valid.json \
         "data.aws.deny"

# Run full test suite
./tests/run_tests.sh
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: OPA Policy Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          sudo mv opa /usr/local/bin/

      - name: Run OPA Tests
        run: |
          cd tests
          ./run_tests.sh

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run Go Tests
        run: go test ./tests/... -v
```

## Policy Development Best Practices

1. **Start with warnings** - Use `warn[msg]` initially, then upgrade to `deny[msg]`
2. **Test both positive and negative cases** - Always create valid and invalid fixtures
3. **Use descriptive messages** - Include resource name and specific violation
4. **Consider environments** - Different rules for dev/staging/prod
5. **Document policies** - Add comments explaining the security rationale
6. **Keep policies focused** - One concern per policy file
7. **Use helper functions** - DRY principle for common checks

## References

- [OPA Testing Guide](https://www.openpolicyagent.org/docs/latest/policy-testing/)
- [Rego Best Practices](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Pulumi Policy as Code](https://www.pulumi.com/docs/guides/crossguard/)
