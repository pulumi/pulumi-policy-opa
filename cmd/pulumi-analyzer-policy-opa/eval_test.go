// Copyright 2025, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// compileModule compiles a single Rego module and returns the compiler.
func compileModule(t *testing.T, name, source string) *ast.Compiler {
	t.Helper()
	compiler, err := ast.CompileModulesWithOpt(
		map[string]string{name: source},
		ast.CompileOpts{
			ParserOptions: ast.ParserOptions{
				RegoVersion: ast.RegoV0,
			},
		},
	)
	if err != nil {
		t.Fatalf("failed to compile rego module: %v", err)
	}
	return compiler
}

// evalRule evaluates a named rule against the given input and returns violation messages.
func evalRule(t *testing.T, compiler *ast.Compiler, pkg, ruleName string, input any) []string {
	t.Helper()

	query := rego.New(
		rego.Query("data."+pkg+"."+ruleName),
		rego.Compiler(compiler),
		rego.Input(input),
		rego.SetRegoVersion(ast.RegoV0),
	)

	rs, err := query.Eval(context.Background())
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var msgs []string
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		if violations, ok := rs[0].Expressions[0].Value.([]any); ok {
			for _, v := range violations {
				s, ok := v.(string)
				if !ok {
					s = fmt.Sprintf("%v", v)
				}
				msgs = append(msgs, s)
			}
		}
	}
	return msgs
}

// evalDeny is a convenience wrapper for evaluating "deny" rules.
func evalDeny(t *testing.T, compiler *ast.Compiler, pkg string, input any) []string {
	t.Helper()
	return evalRule(t, compiler, pkg, "deny", input)
}

// --- Resource-level eval tests ---

// TestEval_PolicyCanAccessType verifies that a Rego policy can read input.type.
func TestEval_PolicyCanAccessType(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    input.type == "aws:s3/bucket:Bucket"
    msg := "matched s3 bucket type"
}
`
	compiler := compileModule(t, "test", module)

	// Should match.
	violations := evalDeny(t, compiler, "test", map[string]any{
		"type": "aws:s3/bucket:Bucket",
	})
	if len(violations) != 1 || violations[0] != "matched s3 bucket type" {
		t.Errorf("expected one violation matching type, got %v", violations)
	}

	// Should not match.
	violations = evalDeny(t, compiler, "test", map[string]any{
		"type": "aws:ec2/instance:Instance",
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for non-matching type, got %v", violations)
	}
}

// TestEval_PolicyCanAccessURN verifies that a Rego policy can read input.urn.
func TestEval_PolicyCanAccessURN(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    contains(input.urn, "production")
    msg := "production resource detected"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"urn": "urn:pulumi:production::my-project::aws:s3/bucket:Bucket::my-bucket",
	})
	if len(violations) != 1 || violations[0] != "production resource detected" {
		t.Errorf("expected production violation, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"urn": "urn:pulumi:staging::my-project::aws:s3/bucket:Bucket::my-bucket",
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for staging URN, got %v", violations)
	}
}

// TestEval_PolicyCanAccessName verifies that a Rego policy can read input.__name.
func TestEval_PolicyCanAccessName(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    contains(lower(input.__name), "prod")
    msg := sprintf("production resource: %s", [input.__name])
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"__name": "prod-database",
	})
	if len(violations) != 1 {
		t.Errorf("expected one violation for prod resource, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"__name": "dev-database",
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for dev resource, got %v", violations)
	}
}

// TestEval_PolicyCanAccessOptions_Protect verifies that a Rego policy can read input.options.protect.
func TestEval_PolicyCanAccessOptions_Protect(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    not input.options.protect
    msg := "resource must be protected"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"protect": false,
		},
	})
	if len(violations) != 1 || violations[0] != "resource must be protected" {
		t.Errorf("expected protect violation, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"protect": true,
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations when protected, got %v", violations)
	}
}

// TestEval_PolicyCanAccessOptions_IgnoreChanges verifies that a Rego policy can
// read input.options.ignoreChanges.
func TestEval_PolicyCanAccessOptions_IgnoreChanges(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    count(input.options.ignoreChanges) > 0
    msg := "ignoreChanges should not be used"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"ignoreChanges": []string{"tags"},
		},
	})
	if len(violations) != 1 {
		t.Errorf("expected violation for ignoreChanges, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"ignoreChanges": []string{},
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violation for empty ignoreChanges, got %v", violations)
	}
}

// TestEval_PolicyCanAccessProvider verifies that a Rego policy can read input.provider.
func TestEval_PolicyCanAccessProvider(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    input.provider.type == "pulumi:providers:aws"
    input.provider.properties.region == "us-east-1"
    msg := "us-east-1 is not allowed"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"provider": map[string]any{
			"type": "pulumi:providers:aws",
			"name": "my-provider",
			"urn":  "urn:pulumi:stack::proj::pulumi:providers:aws::my-provider",
			"properties": map[string]any{
				"region": "us-east-1",
			},
		},
	})
	if len(violations) != 1 || violations[0] != "us-east-1 is not allowed" {
		t.Errorf("expected region violation, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"provider": map[string]any{
			"type": "pulumi:providers:aws",
			"name": "my-provider",
			"urn":  "urn:pulumi:stack::proj::pulumi:providers:aws::my-provider",
			"properties": map[string]any{
				"region": "us-west-2",
			},
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for us-west-2, got %v", violations)
	}
}

// TestEval_PolicyCanAccessOptions_Parent verifies that a Rego policy can read input.options.parent.
func TestEval_PolicyCanAccessOptions_Parent(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    input.options.parent == ""
    msg := "resource must have a parent"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"parent": "",
		},
	})
	if len(violations) != 1 || violations[0] != "resource must have a parent" {
		t.Errorf("expected parent violation, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"parent": "urn:pulumi:stack::proj::type::parent",
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations when parent is set, got %v", violations)
	}
}

// TestEval_NonStringRuleValue verifies that a Rego rule returning a non-string
// value (e.g. a number or object) does not crash the evaluator.
func TestEval_NonStringRuleValue(t *testing.T) {
	module := `
package test

import rego.v1

deny contains val if {
    val := 42
}
`
	compiler := compileModule(t, "test", module)
	e := &evaler{c: compiler}

	pack := &policyPack{
		Name: "test",
		Policies: []*policyRule{
			{Name: "deny", Level: mandatoryRule, Scope: resourceScope},
		},
	}

	results, err := e.evalPolicyPack(context.Background(), pack, map[string]any{}, resourceScope, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].msg != "42" {
		t.Errorf("expected msg '42', got %q", results[0].msg)
	}
}

// TestEval_PolicyCanAccessProperties verifies that a Rego policy can read
// input.properties.<key> as an alternative to input.<key>.
func TestEval_PolicyCanAccessProperties(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    input.properties.acl == "public-read"
    msg := sprintf("bucket %s has public ACL via properties bag", [input.__name])
}
`
	compiler := compileModule(t, "test", module)

	// Should match via input.properties.acl.
	violations := evalDeny(t, compiler, "test", map[string]any{
		"__name": "my-bucket",
		"properties": map[string]any{
			"acl": "public-read",
		},
	})
	if len(violations) != 1 {
		t.Errorf("expected one violation for public ACL, got %v", violations)
	}

	// Should not match.
	violations = evalDeny(t, compiler, "test", map[string]any{
		"__name": "my-bucket",
		"properties": map[string]any{
			"acl": "private",
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for private ACL, got %v", violations)
	}
}

// TestEval_PolicyCanAccessOptions_CustomTimeouts verifies that a Rego policy can
// read input.options.customTimeouts.
func TestEval_PolicyCanAccessOptions_CustomTimeouts(t *testing.T) {
	module := `
package test

import rego.v1

deny contains msg if {
    input.options.customTimeouts.create > 600
    msg := "create timeout exceeds 10 minutes"
}
`
	compiler := compileModule(t, "test", module)

	violations := evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"customTimeouts": map[string]any{
				"create": float64(900),
				"update": float64(0),
				"delete": float64(0),
			},
		},
	})
	if len(violations) != 1 || violations[0] != "create timeout exceeds 10 minutes" {
		t.Errorf("expected timeout violation, got %v", violations)
	}

	violations = evalDeny(t, compiler, "test", map[string]any{
		"options": map[string]any{
			"customTimeouts": map[string]any{
				"create": float64(300),
				"update": float64(0),
				"delete": float64(0),
			},
		},
	})
	if len(violations) != 0 {
		t.Errorf("expected no violations for 5min timeout, got %v", violations)
	}
}

// --- Stack-level eval tests ---

// TestEval_StackPolicyCanAccessResources verifies that a Rego stack rule
// can iterate over input.resources.
func TestEval_StackPolicyCanAccessResources(t *testing.T) {
	module := `
package test

stack_deny[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    r.acl == "public-read"
    msg := sprintf("bucket '%s' is public", [r.__name])
}
`
	compiler := compileModule(t, "test", module)

	input := map[string]any{
		"resources": []any{
			map[string]any{
				"__name": "bucket-1",
				"type":   "aws:s3/bucket:Bucket",
				"acl":    "public-read",
			},
			map[string]any{
				"__name": "bucket-2",
				"type":   "aws:s3/bucket:Bucket",
				"acl":    "private",
			},
		},
	}

	violations := evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 1 || violations[0] != "bucket 'bucket-1' is public" {
		t.Errorf("expected one violation for bucket-1, got %v", violations)
	}
}

// TestEval_StackPolicyCanCountResources verifies that a Rego stack rule
// can count resources.
func TestEval_StackPolicyCanCountResources(t *testing.T) {
	module := `
package test

stack_deny[msg] {
    count(input.resources) > 2
    msg := sprintf("too many resources: %d", [count(input.resources)])
}
`
	compiler := compileModule(t, "test", module)

	// 3 resources — should violate.
	input := map[string]any{
		"resources": []any{
			map[string]any{"__name": "r1", "type": "a"},
			map[string]any{"__name": "r2", "type": "b"},
			map[string]any{"__name": "r3", "type": "c"},
		},
	}
	violations := evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 1 {
		t.Errorf("expected one violation for 3 resources, got %v", violations)
	}

	// 2 resources — should pass.
	input["resources"] = []any{
		map[string]any{"__name": "r1", "type": "a"},
		map[string]any{"__name": "r2", "type": "b"},
	}
	violations = evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 0 {
		t.Errorf("expected no violations for 2 resources, got %v", violations)
	}
}

// TestEval_StackPolicyCanFilterByType verifies that a Rego stack rule
// can filter resources by type.
func TestEval_StackPolicyCanFilterByType(t *testing.T) {
	module := `
package test

stack_deny[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 1
    msg := sprintf("too many S3 buckets: %d", [count(buckets)])
}
`
	compiler := compileModule(t, "test", module)

	input := map[string]any{
		"resources": []any{
			map[string]any{"__name": "bucket-1", "type": "aws:s3/bucket:Bucket"},
			map[string]any{"__name": "bucket-2", "type": "aws:s3/bucket:Bucket"},
			map[string]any{"__name": "instance-1", "type": "aws:ec2/instance:Instance"},
		},
	}

	violations := evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 1 {
		t.Errorf("expected one violation for 2 buckets, got %v", violations)
	}
}

// TestEval_StackPolicyCanAccessDependencies verifies that a Rego stack rule
// can read resource dependencies.
func TestEval_StackPolicyCanAccessDependencies(t *testing.T) {
	module := `
package test

stack_deny[msg] {
    r := input.resources[_]
    dep := r.dependencies[_]
    contains(dep, "securityGroup")
    msg := sprintf("resource '%s' depends on a security group", [r.__name])
}
`
	compiler := compileModule(t, "test", module)

	input := map[string]any{
		"resources": []any{
			map[string]any{
				"__name": "my-instance",
				"type":   "aws:ec2/instance:Instance",
				"dependencies": []any{
					"urn:pulumi:stack::proj::aws:ec2/securityGroup:SecurityGroup::my-sg",
				},
			},
		},
	}

	violations := evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 1 {
		t.Errorf("expected one violation for sg dependency, got %v", violations)
	}
}

// TestEval_StackPolicyCanAccessPropertyDependencies verifies that a Rego stack
// rule can read per-property dependencies.
func TestEval_StackPolicyCanAccessPropertyDependencies(t *testing.T) {
	module := `
package test

stack_deny[msg] {
    r := input.resources[_]
    deps := r.propertyDependencies.subnetId
    count(deps) > 0
    msg := sprintf("resource '%s' has subnetId dependencies", [r.__name])
}
`
	compiler := compileModule(t, "test", module)

	input := map[string]any{
		"resources": []any{
			map[string]any{
				"__name": "my-instance",
				"type":   "aws:ec2/instance:Instance",
				"propertyDependencies": map[string]any{
					"subnetId": []any{
						"urn:pulumi:stack::proj::aws:ec2/subnet:Subnet::my-subnet",
					},
				},
			},
		},
	}

	violations := evalRule(t, compiler, "test", "stack_deny", input)
	if len(violations) != 1 {
		t.Errorf("expected one violation, got %v", violations)
	}
}

// TestEval_StackPolicyScopeFiltering verifies that evalPolicyPack with stackScope
// only evaluates stack rules, not resource rules.
func TestEval_StackPolicyScopeFiltering(t *testing.T) {
	module := `
package test

deny[msg] {
    msg := "resource violation"
}

stack_deny[msg] {
    msg := "stack violation"
}
`
	dir := writeRegoFile(t, "policy.rego", module)
	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	// Evaluate with stack scope — should only get stack violations.
	input := map[string]any{"resources": []any{}}
	results, err := e.evalPolicyPack(context.Background(), pack, input, stackScope, nil)
	if err != nil {
		t.Fatalf("evalPolicyPack failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].msg != "stack violation" {
		t.Errorf("expected 'stack violation', got %q", results[0].msg)
	}
}

// TestEval_ResourcePolicyScopeFiltering verifies that evalPolicyPack with resourceScope
// only evaluates resource rules, not stack rules.
func TestEval_ResourcePolicyScopeFiltering(t *testing.T) {
	module := `
package test

deny[msg] {
    msg := "resource violation"
}

stack_deny[msg] {
    msg := "stack violation"
}
`
	dir := writeRegoFile(t, "policy.rego", module)
	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	// Evaluate with resource scope — should only get resource violations.
	input := map[string]any{"acl": "test"}
	results, err := e.evalPolicyPack(context.Background(), pack, input, resourceScope, nil)
	if err != nil {
		t.Fatalf("evalPolicyPack failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].msg != "resource violation" {
		t.Errorf("expected 'resource violation', got %q", results[0].msg)
	}
}

// TestEval_NonStringRuleValue verifies that non-string values returned by OPA
// rules (e.g., integers) are converted to strings instead of causing a panic.

