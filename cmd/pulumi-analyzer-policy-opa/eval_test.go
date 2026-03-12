// Copyright 2026, Pulumi Corporation.
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
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
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

	rs, err := query.Eval(t.Context())
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

func TestEval_ResourcePolicy(t *testing.T) {
	t.Parallel()

	t.Run("AccessType", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessURN", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessName", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessOptions/Protect", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessOptions/IgnoreChanges", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessProvider", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessOptions/Parent", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("NonStringRuleValue", func(t *testing.T) {
		t.Parallel()
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

		results, err := e.evalPolicyPack(t.Context(), pack, map[string]any{}, resourceScope, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}

		if results[0].msg != "42" {
			t.Errorf("expected msg '42', got %q", results[0].msg)
		}
	})

	t.Run("AccessProperties", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessOptions/CustomTimeouts", func(t *testing.T) {
		t.Parallel()
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
	})
}

func TestEval_StackPolicy(t *testing.T) {
	t.Parallel()

	t.Run("AccessResources", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("CountResources", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("FilterByType", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessDependencies", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("AccessPropertyDependencies", func(t *testing.T) {
		t.Parallel()
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
	})

	t.Run("StackScopeFiltering", func(t *testing.T) {
		t.Parallel()
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
		results, err := e.evalPolicyPack(t.Context(), pack, input, stackScope, nil)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].msg != "stack violation" {
			t.Errorf("expected 'stack violation', got %q", results[0].msg)
		}
	})

	t.Run("ResourceScopeFiltering", func(t *testing.T) {
		t.Parallel()
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
		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, nil)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].msg != "resource violation" {
			t.Errorf("expected 'resource violation', got %q", results[0].msg)
		}
	})
}

func TestExtractViolationMessage(t *testing.T) {
	t.Parallel()

	t.Run("String", func(t *testing.T) {
		t.Parallel()
		msg := extractViolationMessage("plain string")
		if msg != "plain string" {
			t.Errorf("expected 'plain string', got %q", msg)
		}
	})

	t.Run("MapWithMsg", func(t *testing.T) {
		t.Parallel()
		msg := extractViolationMessage(map[string]any{"msg": "violation found", "details": map[string]any{}})
		if msg != "violation found" {
			t.Errorf("expected 'violation found', got %q", msg)
		}
	})

	t.Run("MapWithoutMsg", func(t *testing.T) {
		t.Parallel()
		msg := extractViolationMessage(map[string]any{"details": "something"})
		if msg == "" {
			t.Error("expected non-empty message for map without msg key")
		}
	})

	t.Run("MapWithNonStringMsg", func(t *testing.T) {
		t.Parallel()
		// msg key exists but is not a string — should fall back to fmt.Sprintf.
		msg := extractViolationMessage(map[string]any{"msg": 42})
		if msg == "" {
			t.Error("expected non-empty message for non-string msg")
		}
	})

	t.Run("Integer", func(t *testing.T) {
		t.Parallel()
		msg := extractViolationMessage(42)
		if msg != "42" {
			t.Errorf("expected '42', got %q", msg)
		}
	})

	t.Run("Bool", func(t *testing.T) {
		t.Parallel()
		msg := extractViolationMessage(true)
		if msg != "true" {
			t.Errorf("expected 'true', got %q", msg)
		}
	})
}

func TestCloneInputWithParameters(t *testing.T) {
	t.Parallel()

	t.Run("MapInput", func(t *testing.T) {
		t.Parallel()
		input := map[string]any{
			"review": map[string]any{"object": map[string]any{}},
		}
		params := map[string]any{"maxReplicas": float64(3)}

		result := cloneInputWithParameters(input, params)

		m, ok := result.(map[string]any)
		if !ok {
			t.Fatal("expected result to be a map")
		}

		// Original input should not be modified.
		if _, exists := input["parameters"]; exists {
			t.Error("original input should not be modified")
		}

		// Clone should have parameters.
		p, ok := m["parameters"].(map[string]any)
		if !ok {
			t.Fatal("expected parameters in clone")
		}
		if p["maxReplicas"] != float64(3) {
			t.Errorf("expected maxReplicas=3, got %v", p["maxReplicas"])
		}

		// Clone should preserve existing keys.
		if _, ok := m["review"]; !ok {
			t.Error("expected review key preserved in clone")
		}
	})

	t.Run("NonMapInput", func(t *testing.T) {
		t.Parallel()
		input := "not a map"
		params := map[string]any{"key": "value"}

		result := cloneInputWithParameters(input, params)
		if result != "not a map" {
			t.Errorf("expected non-map input returned unchanged, got %v", result)
		}
	})

	t.Run("NilInput", func(t *testing.T) {
		t.Parallel()
		params := map[string]any{"key": "value"}
		result := cloneInputWithParameters(nil, params)
		if result != nil {
			t.Errorf("expected nil returned for nil input, got %v", result)
		}
	})
}

func TestEval_GatekeeperViolationMap(t *testing.T) {
	t.Parallel()

	// End-to-end test: Gatekeeper-style violation rule through the eval pipeline.
	module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    not input.review.object.metadata.labels["app"]
    msg := "missing required label: app"
}
`
	compiler := compileModule(t, "test", module)
	e := &evaler{c: compiler}

	pack := &policyPack{
		Name: "test",
		Policies: []*policyRule{
			{Name: "violation", Level: mandatoryRule, Scope: resourceScope},
		},
	}

	input := map[string]any{
		"review": map[string]any{
			"object": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{},
				},
			},
		},
	}

	results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].msg != "missing required label: app" {
		t.Errorf("expected violation message, got %q", results[0].msg)
	}
}

func TestEval_InputParameters(t *testing.T) {
	t.Parallel()

	t.Run("Injected", func(t *testing.T) {
		t.Parallel()

		// Gatekeeper-style rule accessing input.parameters.
		module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    max := input.parameters.maxReplicas
    input.review.object.spec.replicas > max
    msg := sprintf("replicas %d exceeds max %d", [input.review.object.spec.replicas, max])
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		pack.InputFormat = InputFormatKubernetesAdmission

		config := map[string]plugin.AnalyzerPolicyConfig{
			"violation": {
				Properties: map[string]any{
					"maxReplicas": float64(3),
				},
			},
		}

		// Input with replicas=5 should violate.
		input := map[string]any{
			"review": map[string]any{
				"object": map[string]any{
					"spec": map[string]any{
						"replicas": float64(5),
					},
				},
			},
		}

		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(results))
		}
		if results[0].msg != "replicas 5 exceeds max 3" {
			t.Errorf("unexpected message: %s", results[0].msg)
		}

		// Input with replicas=2 should pass.
		input = map[string]any{
			"review": map[string]any{
				"object": map[string]any{
					"spec": map[string]any{
						"replicas": float64(2),
					},
				},
			},
		}
		results, err = e.evalPolicyPack(t.Context(), pack, input, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 violations, got %d", len(results))
		}
	})

	t.Run("NotInjectedWhenNonAdmissionFormat", func(t *testing.T) {
		t.Parallel()

		// Rule references input.parameters but pack is NOT kubernetes-admission.
		// Parameters should NOT be injected, so the rule should not fire.
		module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    max := input.parameters.maxReplicas
    input.replicas > max
    msg := "too many replicas"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		// InputFormat is "" (default) — parameters should NOT be injected.

		config := map[string]plugin.AnalyzerPolicyConfig{
			"violation": {
				Properties: map[string]any{
					"maxReplicas": float64(3),
				},
			},
		}

		input := map[string]any{"replicas": float64(5)}
		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		// Rule should not fire because input.parameters is undefined (not injected).
		if len(results) != 0 {
			t.Errorf("expected 0 violations (parameters not injected without admission format), got %d", len(results))
		}
	})

	t.Run("NotInjectedWhenRuleNotInConfig", func(t *testing.T) {
		t.Parallel()

		// Admission format is active, but the rule has no config entry.
		// Parameters should not be injected, so rule should not fire.
		module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    max := input.parameters.maxReplicas
    input.review.object.spec.replicas > max
    msg := "too many replicas"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		pack.InputFormat = InputFormatKubernetesAdmission

		// Config exists but has no entry for "violation".
		config := map[string]plugin.AnalyzerPolicyConfig{
			"other_rule": {
				Properties: map[string]any{"maxReplicas": float64(3)},
			},
		}

		input := map[string]any{
			"review": map[string]any{
				"object": map[string]any{
					"spec": map[string]any{"replicas": float64(5)},
				},
			},
		}
		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 violations (no config for this rule), got %d", len(results))
		}
	})

	t.Run("NotInjectedWhenPropertiesEmpty", func(t *testing.T) {
		t.Parallel()

		// Admission format active, rule has config entry but Properties is empty.
		module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    max := input.parameters.maxReplicas
    input.review.object.spec.replicas > max
    msg := "too many replicas"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		pack.InputFormat = InputFormatKubernetesAdmission

		config := map[string]plugin.AnalyzerPolicyConfig{
			"violation": {
				Properties: map[string]any{},
			},
		}

		input := map[string]any{
			"review": map[string]any{
				"object": map[string]any{
					"spec": map[string]any{"replicas": float64(5)},
				},
			},
		}
		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 violations (empty properties), got %d", len(results))
		}
	})

	t.Run("NilPolicyConfig", func(t *testing.T) {
		t.Parallel()

		// Admission format active but policyConfig is nil.
		// Should not crash, parameters not injected.
		module := `
package test

import rego.v1

violation contains {"msg": msg} if {
    not input.review.object.metadata.labels["app"]
    msg := "no app label"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		pack.InputFormat = InputFormatKubernetesAdmission

		input := map[string]any{
			"review": map[string]any{
				"object": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{},
					},
				},
			},
		}
		results, err := e.evalPolicyPack(t.Context(), pack, input, resourceScope, nil)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(results))
		}
	})
}
