# Getting Started with OPA Policy Tests

This guide helps you quickly get started testing OPA policies for Pulumi.

## What's Included

This test corpus provides **comprehensive security and compliance policies** for:

- ✅ **AWS** (S3, EC2, RDS, IAM, Security Groups)
- ✅ **Azure Native** (Storage, Compute, Network, SQL)
- ✅ **Kubernetes** (Pod Security, Resources, Labels, Images)

**13 policy files** | **20 test fixtures** | **4 integration tests**

## Quick Start (5 minutes)

### 1. Test Policies with OPA CLI

```bash
# Install OPA
brew install opa  # macOS
# OR
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa && sudo mv opa /usr/local/bin/

# Run tests
cd tests
./run_tests.sh
```

**Expected output:**
```
Testing: AWS: s3_valid.json ... PASS
Testing: AWS: s3_invalid_public.json ... PASS (violations found)
Testing: AWS: ec2_valid.json ... PASS
...
All tests passed!
```

### 2. Test with Pulumi (Integration Tests)

```bash
# Prerequisites: Install Pulumi and Node.js
# https://www.pulumi.com/docs/get-started/install/

# Build the analyzer
cd ../..
go build -o pulumi-analyzer-policy-opa ./cmd/pulumi-analyzer-policy-opa

# Run integration tests
cd tests/integration
./run_integration_tests.sh
```

## Example: Testing an AWS S3 Policy

### Policy (tests/aws/policies/s3_security.rego)

```rego
package aws

# S3 Bucket must not have public-read ACL
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not have public-read ACL", [input.__name])
}
```

### Test Fixture (tests/aws/fixtures/s3_invalid_public.json)

```json
{
  "__name": "public-bucket",
  "type": "aws:s3/bucket:Bucket",
  "acl": "public-read"
}
```

### Run Test

```bash
cd tests/aws
opa eval --data policies/s3_security.rego \
         --input fixtures/s3_invalid_public.json \
         "data.aws.deny"
```

**Output:**
```json
[
  "S3 bucket 'public-bucket' must not have public-read ACL"
]
```

## Using Policies with Your Pulumi Projects

### Method 1: Local Policy Pack

```bash
# In your Pulumi project directory
pulumi preview --policy-pack /path/to/tests/aws
```

### Method 2: Publish to Pulumi Cloud

```bash
cd tests/aws
pulumi policy publish
```

Then enable it organization-wide in Pulumi Cloud.

## Understanding Test Results

### ✅ Valid Fixtures (Should Pass)

Files like `s3_valid.json`, `deployment_valid.json` represent **compliant** resources:
- Should produce **zero violations**
- If they fail, the policy may be too strict

### ❌ Invalid Fixtures (Should Fail)

Files like `s3_invalid_public.json`, `deployment_invalid_privileged.json` represent **non-compliant** resources:
- Should produce **one or more violations**
- If they pass, the policy isn't catching the issue

## Common Use Cases

### 1. Enforce S3 Bucket Security

**Policy:** `tests/aws/policies/s3_security.rego`

Enforces:
- ✅ No public access
- ✅ Encryption at rest
- ✅ Versioning for production
- ✅ Access logging

### 2. Kubernetes Pod Security Standards

**Policy:** `tests/kubernetes/policies/pod_security.rego`

Enforces:
- ✅ No privileged containers
- ✅ Drop all capabilities
- ✅ Run as non-root
- ✅ Read-only root filesystem

### 3. Azure Storage Security

**Policy:** `tests/azure/policies/storage_security.rego`

Enforces:
- ✅ HTTPS-only traffic
- ✅ TLS 1.2 minimum
- ✅ No public blob access
- ✅ Encryption enabled

## Customizing Policies

### 1. Adjust Severity

Change `deny[msg]` to `warn[msg]` to make a policy advisory:

```rego
# Before (mandatory - blocks deployment)
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.versioning
    msg := "Bucket must have versioning"
}

# After (advisory - shows warning only)
warn[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.versioning
    msg := "Bucket should have versioning"
}
```

### 2. Add Environment-Specific Rules

```rego
# Only enforce for production
deny[msg] {
    input.type == "aws:rds/instance:Instance"
    contains(lower(input.__name), "prod")
    not input.multiAz
    msg := "Production RDS must have Multi-AZ enabled"
}
```

### 3. Add Allowed Values

```rego
# Restrict to specific instance types
allowed_instance_types := {"t3.medium", "t3.large", "m5.large"}

deny[msg] {
    input.type == "aws:ec2/instance:Instance"
    not input.instanceType in allowed_instance_types
    msg := sprintf("Instance type %s not allowed", [input.instanceType])
}
```

## Testing Your Custom Policies

### 1. Create a Test Fixture

```bash
# Create a JSON file matching your resource structure
cat > tests/aws/fixtures/my_resource_test.json <<EOF
{
  "__name": "test-resource",
  "type": "aws:service:Resource",
  "property": "value"
}
EOF
```

### 2. Test Immediately

```bash
opa eval --data tests/aws/policies/ \
         --input tests/aws/fixtures/my_resource_test.json \
         "data.aws.deny"
```

### 3. Add to Test Suite

The test runner automatically picks up new fixtures:

```bash
cd tests
./run_tests.sh
```

## Troubleshooting

### Issue: "OPA not found"

**Solution:**
```bash
brew install opa  # macOS
# OR download from https://www.openpolicyagent.org/downloads/
```

### Issue: "Pulumi not found"

**Solution:**
```bash
# Install Pulumi CLI
curl -fsSL https://get.pulumi.com | sh
```

### Issue: Tests pass when they should fail

**Possible causes:**
1. Policy rule condition is too narrow
2. Fixture doesn't match the resource type exactly
3. Property names don't match

**Debug:**
```bash
# See what OPA is evaluating
opa eval --data policies/ --input fixtures/test.json --format pretty "data"
```

### Issue: Tests fail when they should pass

**Possible causes:**
1. Policy rule is too strict
2. Fixture is missing required properties
3. Property values don't match expected format

## Next Steps

1. **Explore Policies**: Browse `tests/*/policies/*.rego` files
2. **Review Fixtures**: Check `tests/*/fixtures/*.json` for examples
3. **Run Tests**: Execute `./run_tests.sh` to validate
4. **Customize**: Modify policies for your requirements
5. **Integrate**: Use with Pulumi projects via `pulumi preview --policy-pack`

## Learn More

- 📚 [Complete Test Index](TEST_INDEX.md) - Full list of all policies and tests
- 📖 [Detailed README](README.md) - In-depth documentation
- 🔗 [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- 🔗 [Pulumi CrossGuard](https://www.pulumi.com/docs/guides/crossguard/)

## Support

Found an issue or have questions?
- Open an issue on GitHub
- Review the [Test Index](TEST_INDEX.md) for detailed policy information
- Check OPA documentation for Rego language help

---

**Happy Policy Testing! 🚀**
