# Integration Tests with Pulumi

These tests use `pulumi preview` to actually run the OPA policy analyzer against real Pulumi programs.

## Prerequisites

1. Install Pulumi CLI: https://www.pulumi.com/docs/get-started/install/
2. Build the OPA analyzer plugin
3. Set up test programs

## Running Integration Tests

```bash
# Build the analyzer plugin
cd ../..
go build -o pulumi-analyzer-policy-opa ./cmd/pulumi-analyzer-policy-opa

# Run integration tests
cd tests/integration
./run_integration_tests.sh
```

## Test Structure

Each test consists of:
- A Pulumi program (TypeScript, Python, or Go)
- A policy pack to test against
- Expected outcomes (pass/fail)
