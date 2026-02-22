# Plan: Support Writing Rules That Process the Entire Stack

**Issue:** https://github.com/pulumi/pulumi-policy-opa/issues/4
**Branch:** `craig/opa-stack-policies`
**Date:** 2026-02-17

## Problem Statement

Currently, OPA policies only evaluate individual resources via the `Analyze()` method. Each resource is checked in isolation. However, the Pulumi Policy as Code model also supports **stack-level policies** via `AnalyzeStack()`, which receives *all* resources at once after a successful preview or update. This enables policies that:

- Enforce cross-resource relationships (e.g., "every S3 bucket must have a corresponding logging bucket")
- Validate stack-wide constraints (e.g., "no more than 5 RDS instances per stack")
- Check resource dependency graphs (e.g., "database must not depend on application resources")
- Enforce naming conventions across all resources (e.g., "all resources must have a `team` tag")

The `AnalyzeStack()` method is currently stubbed out and returns an empty response.

## Alignment with Python and TypeScript Pulumi Policy SDKs

Research into the official Pulumi Policy SDKs (`@pulumi/policy` for TypeScript, `pulumi_policy` for Python) reveals the following conventions that our OPA implementation should align with:

### SDK Conventions

| Concept | TypeScript SDK | Python SDK | OPA Implementation |
|---|---|---|---|
| **Resource policy type** | `ResourceValidationPolicy` (with `validateResource` callback) | `ResourceValidationPolicy` (with `validate` callback) | `deny[msg]` / `warn[msg]` rule prefix |
| **Stack policy type** | `StackValidationPolicy` (with `validateStack` callback) | `StackValidationPolicy` (with `validate` callback) | `stack_deny[msg]` / `stack_warn[msg]` rule prefix |
| **Type discrimination** | Duck typing via `isResourcePolicy()` / `isStackPolicy()` type guards | Class type (`isinstance()`) | Regex-based rule name matching |
| **Protocol-level type** | `PolicyType.POLICY_TYPE_RESOURCE` / `POLICY_TYPE_STACK` in protobuf | Same protobuf enum | `AnalyzerPolicyInfo.Type` field set to `AnalyzerPolicyTypeResource` / `AnalyzerPolicyTypeStack` |
| **Enforcement levels** | `"advisory"` / `"mandatory"` / `"remediate"` / `"disabled"` | `EnforcementLevel.ADVISORY` / `.MANDATORY` / `.REMEDIATE` / `.DISABLED` | `advisory` / `mandatory` (remediate/disabled not applicable) |
| **Stack input** | `StackValidationArgs.resources: PolicyResource[]` | `StackValidationArgs.resources: List[PolicyResource]` | `input.resources` array in Rego |
| **Stack resource fields** | `parent`, `dependencies`, `propertyDependencies` on each `PolicyResource` | Same fields on each `PolicyResource` | Same fields on each resource in the `input.resources` array |
| **Stack violation URN** | Optional 2nd arg to `reportViolation(msg, urn?)` | Optional 2nd arg to `report_violation(msg, urn?)` | Included in the violation message string by the policy author |
| **Policy naming** | Kebab-case (e.g., `"s3-no-public-read"`) | Kebab-case (e.g., `"s3-no-public-read"`) | Rego rule names use snake_case per Rego convention (e.g., `deny_no_public_read`) |
| **Remediation** | Supported for resource policies only; stack policies with remediate treated as mandatory | Same | Not applicable (OPA analyzer does not support remediation) |

### Key Takeaways for OPA Implementation

1. **Protocol-level `PolicyType` is required.** The Go SDK's `AnalyzerPolicyInfo` struct has a `Type` field (`AnalyzerPolicyType`). We must set this to `AnalyzerPolicyTypeResource` for resource-level rules and `AnalyzerPolicyTypeStack` for stack-level rules in `GetAnalyzerInfo()`. This tells the Pulumi engine which policies to invoke via `Analyze()` vs `AnalyzeStack()`.

2. **Stack input schema matches SDK conventions.** Both SDKs pass all resources as `args.resources` (an array of `PolicyResource` objects). Our `input.resources` array in Rego follows this same pattern.

3. **Stack resource fields match SDK conventions.** Both SDKs provide `parent`, `dependencies`, and `propertyDependencies` on each stack resource. Our enriched input mirrors this.

4. **Rule naming uses Rego conventions (snake_case) rather than SDK conventions (kebab-case).** This is appropriate because Rego identifiers cannot contain hyphens. The `stack_` prefix is an OPA-specific convention since Rego lacks the class/interface distinction used by the TypeScript and Python SDKs.

5. **Stack policies cannot remediate.** Both SDKs treat stack policies with `remediate` enforcement level as `mandatory`. Since our OPA analyzer does not support remediation at all, this is not a concern.

## Design Decisions

### 1. Rule Naming Convention for Stack Policies

**Approach:** Introduce new rule name prefixes `stack_deny` and `stack_warn` to distinguish stack-level rules from resource-level rules. This is the OPA-specific equivalent of the TypeScript/Python SDKs' separate `StackValidationPolicy` class — since Rego has no class system, we use rule name prefixes instead.

| Rule Pattern | Level | Scope | Evaluated In |
|---|---|---|---|
| `deny[msg]`, `deny_<suffix>[msg]`, `violation[msg]` | Mandatory | Per-resource | `Analyze()` |
| `warn[msg]`, `warn_<suffix>[msg]` | Advisory | Per-resource | `Analyze()` |
| `stack_deny[msg]`, `stack_deny_<suffix>[msg]`, `stack_violation[msg]` | Mandatory | Whole stack | `AnalyzeStack()` |
| `stack_warn[msg]`, `stack_warn_<suffix>[msg]` | Advisory | Whole stack | `AnalyzeStack()` |

This is backward compatible — existing resource-level rules are unaffected. Stack rules coexist in the same `.rego` files and package, sharing helper functions.

### 2. Stack Policy Input Schema

Stack-level rules receive a different input than resource-level rules. Instead of a single resource, the input is an object containing a `resources` array:

```json
{
  "resources": [
    {
      "__name": "prod-bucket",
      "type": "aws:s3/bucket:Bucket",
      "urn": "urn:pulumi:prod::proj::aws:s3/bucket:Bucket::prod-bucket",
      "options": { "protect": true, ... },
      "provider": { "type": "pulumi:providers:aws", ... },
      "dependencies": [
        "urn:pulumi:prod::proj::aws:s3/bucket:Bucket::logging-bucket"
      ],
      "propertyDependencies": {
        "loggingConfiguration": [
          "urn:pulumi:prod::proj::aws:s3/bucket:Bucket::logging-bucket"
        ]
      },
      "acl": "private",
      ...
    },
    {
      "__name": "logging-bucket",
      "type": "aws:s3/bucket:Bucket",
      ...
    }
  ]
}
```

Each resource in the array has:
- All fields from `buildOPAInput()` (properties, type, urn, __name, options, provider)
- `dependencies`: array of URN strings this resource depends on (from `AnalyzerStackResource.Dependencies`)
- `propertyDependencies`: map of property name to array of URN strings (from `AnalyzerStackResource.PropertyDependencies`)

Note: `AnalyzerStackResource` has a top-level `Parent` field, but `AnalyzerResource.Options` already contains `Parent`. We use `options.parent` for consistency with the resource-level input schema and avoid adding a duplicate top-level field. If they differ, the `AnalyzerStackResource.Parent` value will be used to override `options.parent`.

### 3. Evaluation Strategy

- `Analyze()` continues to evaluate **only** resource-level rules (`deny`, `warn`, etc.) — unchanged.
- `AnalyzeStack()` evaluates **only** stack-level rules (`stack_deny`, `stack_warn`, etc.).
- Stack-level rules are **not** re-run per resource. They see the complete set and run once.
- If no stack-level rules exist in the policy pack, `AnalyzeStack()` short-circuits and returns an empty response (no overhead).

### 4. Backward Compatibility

- Existing policy packs with no `stack_*` rules work identically to today.
- The `policyRule` struct gains a `Scope` field to track whether a rule is resource-level or stack-level.
- `evalPolicyPack()` accepts a `scope` parameter to filter which rules to evaluate.

---

## Phase 1: Define Test Cases

### 1.1 Unit Tests — `buildStackOPAInput()` (`cmd/pulumi-analyzer-policy-opa/analyzer_test.go`)

Tests for the new function that constructs the stack-level input from `[]plugin.AnalyzerStackResource`.

| # | Test Name | Description | Expected Outcome |
|---|-----------|-------------|------------------|
| 1 | `TestBuildStackInput_BasicResources` | Build stack input from 2 `AnalyzerStackResource` objects | `input["resources"]` is an array of length 2, each containing enriched resource fields |
| 2 | `TestBuildStackInput_IncludesDependencies` | Build stack input from a resource with `Dependencies` set | Each resource map includes `dependencies` as `[]string` of URNs |
| 3 | `TestBuildStackInput_IncludesPropertyDependencies` | Build stack input from a resource with `PropertyDependencies` set | Each resource map includes `propertyDependencies` as `map[string][]string` |
| 4 | `TestBuildStackInput_EmptyResources` | Build stack input from an empty slice | `input["resources"]` is an empty array |
| 5 | `TestBuildStackInput_ParentOverride` | Build stack input where `AnalyzerStackResource.Parent` differs from `Options.Parent` | `options.parent` reflects the `AnalyzerStackResource.Parent` value |
| 6 | `TestBuildStackInput_NilDependencies` | Build stack input when Dependencies and PropertyDependencies are nil | `dependencies` is nil/absent, `propertyDependencies` is nil/absent |

### 1.2 Rule Classification Tests (`cmd/pulumi-analyzer-policy-opa/policy_test.go`)

Tests for the policy loading logic that classifies rules by scope.

| # | Test Name | Description | Expected Outcome |
|---|-----------|-------------|---|
| 7 | `TestLoadPolicies_StackDenyRule` | Load a rego file with `stack_deny[msg]` | Rule classified as mandatory, stack scope |
| 8 | `TestLoadPolicies_StackWarnRule` | Load a rego file with `stack_warn[msg]` | Rule classified as advisory, stack scope |
| 9 | `TestLoadPolicies_StackDenySuffixRule` | Load a rego file with `stack_deny_no_public_buckets[msg]` | Rule classified as mandatory, stack scope |
| 10 | `TestLoadPolicies_MixedRules` | Load a rego file with both `deny[msg]` and `stack_deny[msg]` | Both rules present, correctly scoped |
| 11 | `TestLoadPolicies_StackViolationRule` | Load a rego file with `stack_violation[msg]` | Rule classified as mandatory, stack scope |

### 1.3 OPA Evaluation Tests — Stack Rules (`cmd/pulumi-analyzer-policy-opa/eval_test.go`)

Tests that compile and evaluate Rego stack policies against the stack input schema.

| # | Test Name | Description | Expected Outcome |
|---|-----------|-------------|------------------|
| 12 | `TestEval_StackPolicyCanAccessResources` | Rego rule iterates `input.resources` | Rule sees all resources in array |
| 13 | `TestEval_StackPolicyCanCountResources` | Rego rule checks `count(input.resources)` | Correctly counts resources |
| 14 | `TestEval_StackPolicyCanFilterByType` | Rego rule filters `input.resources` by `type` field | Only matching resources processed |
| 15 | `TestEval_StackPolicyCanAccessDependencies` | Rego rule checks resource `dependencies` | Correctly reads dependency URNs |
| 16 | `TestEval_StackPolicyCanAccessPropertyDependencies` | Rego rule checks `propertyDependencies` | Correctly reads per-property deps |
| 17 | `TestEval_StackPolicyScopeFiltering` | Evaluate with scope=stack, pack has both `deny` and `stack_deny` | Only `stack_deny` rules are evaluated |
| 18 | `TestEval_ResourcePolicyScopeFiltering` | Evaluate with scope=resource, pack has both `deny` and `stack_deny` | Only `deny` rules are evaluated |

### 1.4 Fixture-Based Test Cases — Stack Test Suite (`tests/stack/`)

New test suite with stack-level policies and fixtures.

| # | File | Description |
|---|------|-------------|
| 19 | `tests/stack/PulumiPolicy.yaml` | Policy pack manifest for stack tests |
| 20 | `tests/stack/policies/stack_policies.rego` | Stack-level Rego policies (see below) |
| 21 | `tests/stack/fixtures/stack_valid.json` | Stack with proper resource configuration — no violations |
| 22 | `tests/stack/fixtures/stack_invalid_too_many_buckets.json` | Stack with >3 S3 buckets — should violate |
| 23 | `tests/stack/fixtures/stack_invalid_missing_encryption.json` | Stack where some S3 buckets lack encryption — should violate |
| 24 | `tests/stack/fixtures/stack_invalid_orphan_sg.json` | Stack with security group not attached to any instance — should violate |

**Example Rego stack policies** (`stack_policies.rego`):
```rego
package stack

# Stack-level: limit the number of S3 buckets per stack
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}

# Stack-level: all S3 buckets must have encryption
stack_deny_unencrypted_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    not r.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [r.__name])
}

# Stack-level: warn about security groups not referenced in dependencies
stack_warn_orphan_security_groups[msg] {
    sg := input.resources[_]
    sg.type == "aws:ec2/securityGroup:SecurityGroup"
    all_deps := {dep | r := input.resources[_]; dep := r.dependencies[_]}
    not all_deps[sg.urn]
    msg := sprintf("Security group '%s' is not referenced by any resource", [sg.__name])
}
```

### 1.5 Integration Tests — End-to-End with Analyzer (`cmd/pulumi-analyzer-policy-opa/analyzer_integration_test.go`)

| # | Test Name | Description |
|---|-----------|-------------|
| 25 | `TestAnalyzer_AnalyzeStack_BasicViolation` | Call `AnalyzeStack()` with resources that violate a `stack_deny` rule — verify diagnostics returned |
| 26 | `TestAnalyzer_AnalyzeStack_NoViolation` | Call `AnalyzeStack()` with compliant resources — verify empty diagnostics |
| 27 | `TestAnalyzer_AnalyzeStack_NoStackRules` | Call `AnalyzeStack()` with a policy pack containing only resource-level rules — verify short-circuit, no errors |
| 28 | `TestAnalyzer_AnalyzeStack_MixedRules` | Policy pack has both `deny` and `stack_deny`. Call `Analyze()` then `AnalyzeStack()` — verify each method only evaluates its scoped rules |
| 29 | `TestAnalyzer_AnalyzeStack_WarnLevel` | Call `AnalyzeStack()` with a `stack_warn` rule — verify diagnostic has Advisory enforcement level |
| 30 | `TestAnalyzer_Analyze_IgnoresStackRules` | Call `Analyze()` with a policy pack containing `stack_deny` rules — verify stack rules are NOT evaluated |
| 31 | `TestAnalyzer_AnalyzeStack_BackwardCompatible` | Call `AnalyzeStack()` with an existing policy pack (resource-only rules) — verify no errors, empty response |
| 32 | `TestAnalyzer_GetAnalyzerInfo_ReportsPolicyTypes` | Call `GetAnalyzerInfo()` with a mixed policy pack — verify resource rules have `AnalyzerPolicyTypeResource` and stack rules have `AnalyzerPolicyTypeStack` |

---

## Phase 2: Implementation Steps

### Step 1: Add `policyScope` type and update `policyRule`

**File:** `cmd/pulumi-analyzer-policy-opa/policy.go`

Add a `policyScope` type to distinguish resource-level from stack-level rules:

```go
type policyScope int

const (
    resourceScope policyScope = 0
    stackScope    policyScope = 1
)
```

Add `Scope` field to `policyRule`:

```go
type policyRule struct {
    Name        string           `json:"name"`
    DisplayName string           `json:"displayName"`
    Description string           `json:"description"`
    Message     string           `json:"message"`
    Level       enforcementLevel `json:"enforcementLevel"`
    Scope       policyScope      `json:"scope"`
}
```

### Step 2: Update rule classification regexes

**File:** `cmd/pulumi-analyzer-policy-opa/policy.go`

Add new regex patterns for stack-level rules:

```go
var (
    denyRulePrefix      = regexp.MustCompile("^(deny|violation)(_[a-zA-Z]+)*$")
    warnRulePrefix      = regexp.MustCompile("^warn(_[a-zA-Z]+)*$")
    stackDenyRulePrefix = regexp.MustCompile("^stack_(deny|violation)(_[a-zA-Z]+)*$")
    stackWarnRulePrefix = regexp.MustCompile("^stack_warn(_[a-zA-Z]+)*$")
)
```

Update the rule classification in `loadPolicyPack()` to check stack prefixes **before** resource prefixes (since `stack_deny` would also match `deny` substring-wise if not careful — but with our anchored regexes this isn't an issue, so order doesn't matter for correctness; checking stack first is just clearer):

```go
var level enforcementLevel
var scope policyScope
if stackDenyRulePrefix.MatchString(ruleName) {
    level = mandatoryRule
    scope = stackScope
} else if stackWarnRulePrefix.MatchString(ruleName) {
    level = advisoryRule
    scope = stackScope
} else if denyRulePrefix.MatchString(ruleName) {
    level = mandatoryRule
    scope = resourceScope
} else if warnRulePrefix.MatchString(ruleName) {
    level = advisoryRule
    scope = resourceScope
} else {
    continue
}
```

### Step 3: Add scope filtering to `evalPolicyPack()`

**File:** `cmd/pulumi-analyzer-policy-opa/eval.go`

Add a `scope` parameter to `evalPolicyPack()` so it only evaluates rules matching the requested scope:

```go
func (e *evaler) evalPolicyPack(
    ctx context.Context,
    pack *policyPack,
    input any,
    scope policyScope,
) ([]evalPolicyResult, error) {
    var results []evalPolicyResult

    for _, rule := range pack.Policies {
        if rule.Scope != scope {
            continue // skip rules not matching requested scope
        }
        // ... rest of evaluation unchanged
    }

    return results, nil
}
```

### Step 4: Update `Analyze()` to pass `resourceScope`

**File:** `cmd/pulumi-analyzer-policy-opa/analyzer.go`

Update the `evalPolicyPack` call in `Analyze()`:

```go
results, err := a.e.evalPolicyPack(context.Background(), a.pack, obj, resourceScope)
```

### Step 5: Create `buildStackOPAInput()` function

**File:** `cmd/pulumi-analyzer-policy-opa/analyzer.go`

New function that constructs the stack-level input:

```go
// buildStackOPAInput constructs the input object passed to OPA stack policy evaluation.
// It creates a map with a "resources" key containing an array of enriched resource objects,
// each including the resource's properties, metadata, dependencies, and property dependencies.
func buildStackOPAInput(resources []plugin.AnalyzerStackResource) map[string]any {
    var resourceList []map[string]any

    for _, sr := range resources {
        obj := buildOPAInput(sr.AnalyzerResource)

        // Override options.parent with the AnalyzerStackResource.Parent if non-empty,
        // as it may provide a more accurate value than Options.Parent.
        if sr.Parent != "" {
            if opts, ok := obj["options"].(map[string]any); ok {
                opts["parent"] = string(sr.Parent)
            }
        }

        // Add stack-level fields.
        if sr.Dependencies != nil {
            deps := make([]string, len(sr.Dependencies))
            for i, d := range sr.Dependencies {
                deps[i] = string(d)
            }
            obj["dependencies"] = deps
        }

        if sr.PropertyDependencies != nil {
            propDeps := make(map[string][]string)
            for k, urns := range sr.PropertyDependencies {
                strs := make([]string, len(urns))
                for i, u := range urns {
                    strs[i] = string(u)
                }
                propDeps[string(k)] = strs
            }
            obj["propertyDependencies"] = propDeps
        }

        resourceList = append(resourceList, obj)
    }

    return map[string]any{
        "resources": resourceList,
    }
}
```

### Step 6: Implement `AnalyzeStack()`

**File:** `cmd/pulumi-analyzer-policy-opa/analyzer.go`

Replace the stub with a full implementation:

```go
func (a *analyzer) AnalyzeStack(resources []plugin.AnalyzerStackResource) (plugin.AnalyzeResponse, error) {
    // Short-circuit if no stack-level rules exist.
    hasStackRules := false
    for _, pol := range a.pack.Policies {
        if pol.Scope == stackScope {
            hasStackRules = true
            break
        }
    }
    if !hasStackRules {
        return plugin.AnalyzeResponse{}, nil
    }

    // Build the stack-level input containing all resources.
    obj := buildStackOPAInput(resources)
    results, err := a.e.evalPolicyPack(context.Background(), a.pack, obj, stackScope)
    if err != nil {
        return plugin.AnalyzeResponse{}, err
    }

    // Translate results into diagnostics.
    var diagnostics []plugin.AnalyzeDiagnostic
    for _, result := range results {
        var level apitype.EnforcementLevel
        if result.level == advisoryRule {
            level = apitype.Advisory
        } else {
            level = apitype.Mandatory
        }
        diagnostics = append(diagnostics, plugin.AnalyzeDiagnostic{
            PolicyName:        result.rule,
            PolicyPackName:    result.pack,
            PolicyPackVersion: VersionString,
            Message:           result.msg,
            EnforcementLevel:  level,
        })
    }

    return plugin.AnalyzeResponse{Diagnostics: diagnostics}, nil
}
```

Note: Stack-level diagnostics do not set `URN` on the diagnostic since the violation applies to the stack as a whole, not a specific resource. If a stack rule identifies a specific resource, the violation message should include the URN/name for context.

### Step 7: Update test runner for stack fixtures

**File:** `tests/test_runner_test.go`

Add stack test suite to `GetTestSuites()` and create `TestStackPolicies()`. The fixture format changes for stack tests — fixtures contain `{"resources": [...]}` instead of a single resource object. Update `runTestSuite()` to handle both single-resource and multi-resource (stack) fixtures, or create a new `runStackTestSuite()` function that uses `stack_deny` as the query instead of `deny`.

Add a new `EvaluateStackPolicy()` function that queries `data.<package>.stack_deny` instead of `data.<package>.deny`.

### Step 8: Create stack test fixtures and policies

Create the `tests/stack/` directory with:
- `PulumiPolicy.yaml`
- `policies/stack_policies.rego`
- `fixtures/stack_valid.json`
- `fixtures/stack_invalid_too_many_buckets.json`
- `fixtures/stack_invalid_missing_encryption.json`
- `fixtures/stack_invalid_orphan_sg.json`

### Step 9: Add unit, eval, and integration tests

Add all tests defined in Phase 1 sections 1.1 through 1.5.

### Step 10: Update `GetAnalyzerInfo()` to report `AnalyzerPolicyType`

**File:** `cmd/pulumi-analyzer-policy-opa/analyzer.go`

The `GetAnalyzerInfo()` method returns policy metadata. The Go SDK's `AnalyzerPolicyInfo` struct has a `Type` field of type `AnalyzerPolicyType`. This must be set correctly so the Pulumi engine knows which policies are resource-level vs stack-level — matching the convention used by the TypeScript and Python SDKs (which set `PolicyType.POLICY_TYPE_RESOURCE` / `POLICY_TYPE_STACK` at the protobuf level).

Update the policy info loop in `GetAnalyzerInfo()`:

```go
func (a *analyzer) GetAnalyzerInfo() (plugin.AnalyzerInfo, error) {
    var policies []plugin.AnalyzerPolicyInfo
    for _, pol := range a.pack.Policies {
        var enforcementLevel apitype.EnforcementLevel
        if pol.Level == advisoryRule {
            enforcementLevel = apitype.Advisory
        } else {
            enforcementLevel = apitype.Mandatory
        }

        var policyType plugin.AnalyzerPolicyType
        if pol.Scope == stackScope {
            policyType = plugin.AnalyzerPolicyTypeStack
        } else {
            policyType = plugin.AnalyzerPolicyTypeResource
        }

        policies = append(policies, plugin.AnalyzerPolicyInfo{
            Name:             pol.Name,
            DisplayName:      pol.DisplayName,
            Description:      pol.Description,
            Message:          pol.Message,
            EnforcementLevel: enforcementLevel,
            Type:             policyType,
        })
    }
    return plugin.AnalyzerInfo{
        Name:        a.pack.Name,
        DisplayName: a.pack.DisplayName,
        Policies:    policies,
    }, nil
}
```

---

## Phase 3: Validation Steps

### 3.1 Run Existing Tests (Regression Check)

```bash
# All existing tests must continue to pass
cd tests && go test -v -run TestAWSPolicies ./...
cd tests && go test -v -run TestAzurePolicies ./...
cd tests && go test -v -run TestKubernetesPolicies ./...
cd tests && go test -v -run TestMetadataPolicies ./...
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestBuildInput ./...
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestEval_PolicyCanAccess ./...
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestAnalyzer_Analyze ./...
```

**Expected:** All existing tests pass without modification.

### 3.2 Run New Unit Tests

```bash
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestBuildStackInput ./...
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestLoadPolicies_Stack ./...
```

**Expected:** All 11 new unit tests pass (tests 1-11).

### 3.3 Run New OPA Evaluation Tests

```bash
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestEval_Stack ./...
```

**Expected:** All 7 new eval tests pass (tests 12-18).

### 3.4 Run New Stack Test Suite

```bash
cd tests && go test -v -run TestStackPolicies ./...
```

**Expected:** Valid fixtures pass, invalid fixtures produce expected violations.

### 3.5 Run New Integration Tests

```bash
cd cmd/pulumi-analyzer-policy-opa && go test -v -run TestAnalyzer_AnalyzeStack ./...
```

**Expected:** All 7 integration tests pass (tests 25-31).

### 3.6 Run Full Test Suite

```bash
make test_all
```

**Expected:** All tests pass — zero regressions, all new tests green.

### 3.7 Build and Lint

```bash
make build
make lint
```

**Expected:** Clean build with no lint errors or warnings.

### 3.8 Manual Smoke Test (Optional)

1. Build the plugin: `make install`
2. Create a Pulumi program that deploys multiple S3 buckets
3. Write a Rego policy with a `stack_deny` rule that limits bucket count
4. Run `pulumi preview --policy-pack <path>` and verify:
   - Resource-level `deny` rules fire per-resource as before
   - Stack-level `stack_deny` rule fires once after all resources are analyzed

---

## Files Modified/Created Summary

| File | Action | Purpose |
|------|--------|---------|
| `cmd/pulumi-analyzer-policy-opa/policy.go` | **Modified** | Add `policyScope` type, stack rule regexes, update `loadPolicyPack()` classification |
| `cmd/pulumi-analyzer-policy-opa/eval.go` | **Modified** | Add `scope` parameter to `evalPolicyPack()` |
| `cmd/pulumi-analyzer-policy-opa/analyzer.go` | **Modified** | Add `buildStackOPAInput()`, implement `AnalyzeStack()`, update `Analyze()` call |
| `cmd/pulumi-analyzer-policy-opa/analyzer_test.go` | **Modified** | Add `TestBuildStackInput_*` tests |
| `cmd/pulumi-analyzer-policy-opa/eval_test.go` | **Modified** | Add `TestEval_Stack*` tests |
| `cmd/pulumi-analyzer-policy-opa/policy_test.go` | **Created** | Rule classification tests for stack rules |
| `cmd/pulumi-analyzer-policy-opa/analyzer_integration_test.go` | **Modified** | Add `TestAnalyzer_AnalyzeStack_*` tests |
| `tests/test_runner_test.go` | **Modified** | Add stack test suite, `EvaluateStackPolicy()`, `TestStackPolicies()` |
| `tests/stack/PulumiPolicy.yaml` | **Created** | Stack test suite manifest |
| `tests/stack/policies/stack_policies.rego` | **Created** | Stack-level Rego policies |
| `tests/stack/fixtures/stack_valid.json` | **Created** | Valid stack fixture |
| `tests/stack/fixtures/stack_invalid_too_many_buckets.json` | **Created** | Too many buckets fixture |
| `tests/stack/fixtures/stack_invalid_missing_encryption.json` | **Created** | Missing encryption fixture |
| `tests/stack/fixtures/stack_invalid_orphan_sg.json` | **Created** | Orphan security group fixture |

---

## Open Questions / Considerations

1. **URN on stack diagnostics:** Stack-level violations don't naturally correspond to a single resource URN. We leave `URN` empty on the `AnalyzeDiagnostic`. This aligns with the TypeScript and Python SDKs, where `reportViolation(msg)` without a URN indicates an overall stack violation. Policy authors should include identifying information (resource name/URN) in the violation message itself for resource-specific stack violations.

2. **Performance:** `AnalyzeStack()` compiles no new policies — it reuses the same compiled `evaler`. The only cost is constructing the resource array and running the stack queries. For large stacks (thousands of resources), the input object could be large, but OPA handles large datasets well.

3. **Mixed packages:** Currently all `.rego` files in a policy pack must use the same package name. This remains true — stack rules and resource rules coexist in the same package. Helper functions (e.g., utility predicates) are shared.

4. **Rule name `stack_violation`:** For symmetry with `deny`/`violation`, we support both `stack_deny` and `stack_violation` as mandatory stack rule prefixes.

5. **Future: stack_warn fixtures:** The initial fixture set focuses on `stack_deny` rules. `stack_warn` rules are tested via integration tests but could benefit from dedicated fixtures in a follow-up.

6. **`AnalyzerPolicyInfo.Type` is critical for Pulumi engine integration.** The TypeScript and Python SDKs both set the protobuf `PolicyType` field to `POLICY_TYPE_RESOURCE` or `POLICY_TYPE_STACK`. Our Go implementation must do the same via `AnalyzerPolicyInfo.Type` so the engine correctly routes `Analyze()` and `AnalyzeStack()` calls. This was confirmed by examining the Go SDK's `AnalyzerPolicyInfo` struct, which has a `Type AnalyzerPolicyType` field with values `AnalyzerPolicyTypeResource` and `AnalyzerPolicyTypeStack`.

7. **Naming convention difference is intentional.** The TypeScript/Python SDKs use kebab-case policy names (e.g., `"s3-no-public-read"`), but Rego identifiers must use snake_case (hyphens are not valid in Rego identifiers). The `stack_` prefix is the natural Rego equivalent of the SDKs' separate `StackValidationPolicy` class.
