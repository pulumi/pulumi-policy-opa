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
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
)

func TestAnalyzer_Analyze(t *testing.T) {
	t.Parallel()

	t.Run("PassesMetadata", func(t *testing.T) {
		t.Parallel()
		// Compile a policy that checks input.urn and input.options.protect.
		regoSource := `
package test_metadata

import rego.v1

deny contains msg if {
    contains(input.urn, "production")
    not input.options.protect
    msg := sprintf("Production resource '%s' must be protected", [input.__name])
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"metadata_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		// Production resource without protect — should produce a violation.
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:production::my-project::aws:s3/bucket:Bucket::prod-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "prod-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
			Options: plugin.AnalyzerResourceOptions{
				Protect: false,
			},
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d: %v", len(resp.Diagnostics), resp.Diagnostics)
		}
		diag := resp.Diagnostics[0]
		if diag.EnforcementLevel != apitype.Mandatory {
			t.Errorf("expected Mandatory enforcement, got %v", diag.EnforcementLevel)
		}
		if diag.Message != "Production resource 'prod-bucket' must be protected" {
			t.Errorf("unexpected message: %s", diag.Message)
		}

		// Production resource with protect — should pass cleanly.
		resp, err = a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:production::my-project::aws:s3/bucket:Bucket::prod-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "prod-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
			Options: plugin.AnalyzerResourceOptions{
				Protect: true,
			},
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics for protected resource, got %d: %v",
				len(resp.Diagnostics), resp.Diagnostics)
		}

		// Staging resource without protect — should pass (no "production" in URN).
		resp, err = a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:staging::my-project::aws:s3/bucket:Bucket::staging-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "staging-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
			Options: plugin.AnalyzerResourceOptions{
				Protect: false,
			},
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics for staging resource, got %d: %v",
				len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("BackwardCompatible", func(t *testing.T) {
		t.Parallel()
		// A policy that only references input properties — no metadata fields.
		regoSource := `
package test_compat

import rego.v1

deny contains msg if {
    input.acl == "public-read"
    msg := "public-read ACL is not allowed"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"compat_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		// Public bucket — should violate.
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:dev::proj::aws:s3/bucket:Bucket::bad-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "bad-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "public-read",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d", len(resp.Diagnostics))
		}
		if resp.Diagnostics[0].Message != "public-read ACL is not allowed" {
			t.Errorf("unexpected message: %s", resp.Diagnostics[0].Message)
		}

		// Private bucket — should pass.
		resp, err = a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:dev::proj::aws:s3/bucket:Bucket::good-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "good-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics, got %d: %v", len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("RegoV0Compatible", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_v0

deny[msg] {
    input.acl == "public-read"
    msg := "v0 rule: public-read ACL is not allowed"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"v0_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile v0 policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		// Public bucket — should violate.
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:dev::proj::aws:s3/bucket:Bucket::bad-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "bad-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "public-read",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d", len(resp.Diagnostics))
		}
		if resp.Diagnostics[0].Message != "v0 rule: public-read ACL is not allowed" {
			t.Errorf("unexpected message: %s", resp.Diagnostics[0].Message)
		}

		// Private bucket — should pass.
		resp, err = a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:dev::proj::aws:s3/bucket:Bucket::good-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "good-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics, got %d: %v", len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("IgnoresStackRules", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_ignore

stack_deny[msg] {
    msg := "this should never fire from Analyze"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"stack_only": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics (stack rules ignored), got %d: %v",
				len(resp.Diagnostics), resp.Diagnostics)
		}
	})
}

// compilePoliciesFromSource compiles Rego source strings into a policyPack and evaler,
// mimicking what loadPolicyPack does but from in-memory sources.
func compilePoliciesFromSource(modules map[string]string) (*policyPack, *evaler, error) {
	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		ParserOptions: ast.ParserOptions{
			RegoVersion: ast.RegoV0,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	var packName string
	var policies []*policyRule
	existing := make(map[string]bool)

	for name, module := range compiler.Modules {
		pkg := module.Package.String()
		if len(pkg) > len("package ") {
			pkg = pkg[len("package "):]
		}
		if packName == "" {
			packName = pkg
		}

		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()
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
			if !existing[ruleName] {
				existing[ruleName] = true
				policies = append(policies, &policyRule{
					Name:        ruleName,
					DisplayName: name,
					Level:       level,
					Scope:       scope,
				})
			}
		}
	}

	pack := &policyPack{
		Name:     packName,
		Policies: policies,
	}
	e := &evaler{c: compiler}
	return pack, e, nil
}

func TestAnalyzer_AnalyzeStack(t *testing.T) {
	t.Parallel()

	t.Run("BasicViolation", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_stack

stack_deny[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 2
    msg := sprintf("Too many S3 buckets: %d (max 2)", [count(buckets)])
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"stack_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
			makeStackResource("bucket-2", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-2"),
			makeStackResource("bucket-3", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-3"),
		}

		resp, err := a.AnalyzeStack(resources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(resp.Diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d: %v", len(resp.Diagnostics), resp.Diagnostics)
		}
		if resp.Diagnostics[0].EnforcementLevel != apitype.Mandatory {
			t.Errorf("expected Mandatory enforcement, got %v", resp.Diagnostics[0].EnforcementLevel)
		}
		if resp.Diagnostics[0].Message != "Too many S3 buckets: 3 (max 2)" {
			t.Errorf("unexpected message: %s", resp.Diagnostics[0].Message)
		}
	})

	t.Run("NoViolation", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_stack

stack_deny[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 5
    msg := "too many buckets"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"stack_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
			makeStackResource("bucket-2", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-2"),
		}

		resp, err := a.AnalyzeStack(resources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics, got %d: %v", len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("NoStackRules", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_resource_only

deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"resource_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
		}

		resp, err := a.AnalyzeStack(resources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics (short-circuit), got %d", len(resp.Diagnostics))
		}
	})

	t.Run("MixedRules", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_mixed

deny[msg] {
    input.acl == "public-read"
    msg := "resource: public ACL not allowed"
}

stack_deny[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 1
    msg := "stack: too many buckets"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"mixed": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		// Analyze() should only fire the resource-level deny rule.
		analyzeResp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bad-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "bad-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "public-read",
			}),
		})
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(analyzeResp.Diagnostics) != 1 {
			t.Fatalf("Analyze: expected 1 diagnostic, got %d", len(analyzeResp.Diagnostics))
		}
		if analyzeResp.Diagnostics[0].Message != "resource: public ACL not allowed" {
			t.Errorf("Analyze: unexpected message: %s", analyzeResp.Diagnostics[0].Message)
		}

		// AnalyzeStack() should only fire the stack-level deny rule.
		stackResources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
			makeStackResource("bucket-2", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-2"),
		}

		stackResp, err := a.AnalyzeStack(stackResources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(stackResp.Diagnostics) != 1 {
			t.Fatalf("AnalyzeStack: expected 1 diagnostic, got %d", len(stackResp.Diagnostics))
		}
		if stackResp.Diagnostics[0].Message != "stack: too many buckets" {
			t.Errorf("AnalyzeStack: unexpected message: %s", stackResp.Diagnostics[0].Message)
		}
	})

	t.Run("WarnLevel", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_warn

stack_warn[msg] {
    count(input.resources) > 1
    msg := "consider reducing resource count"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"warn_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resources := []plugin.AnalyzerStackResource{
			makeStackResource("r1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::r1"),
			makeStackResource("r2", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::r2"),
		}

		resp, err := a.AnalyzeStack(resources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(resp.Diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d", len(resp.Diagnostics))
		}
		if resp.Diagnostics[0].EnforcementLevel != apitype.Advisory {
			t.Errorf("expected Advisory enforcement, got %v", resp.Diagnostics[0].EnforcementLevel)
		}
	})

	t.Run("BackwardCompatible", func(t *testing.T) {
		t.Parallel()
		regoSource := `
package test_compat

deny[msg] {
    input.acl == "public-read"
    msg := "public-read ACL is not allowed"
}

warn[msg] {
    not input.tags
    msg := "resource should have tags"
}
`
		pack, e, err := compilePoliciesFromSource(map[string]string{
			"compat_check": regoSource,
		})
		if err != nil {
			t.Fatalf("failed to compile policy: %v", err)
		}

		a := NewAnalyzer(pack, e)

		resources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
		}

		resp, err := a.AnalyzeStack(resources)
		if err != nil {
			t.Fatalf("AnalyzeStack returned error: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics (resource-only pack), got %d: %v",
				len(resp.Diagnostics), resp.Diagnostics)
		}
	})
}

func TestAnalyzer_Name(t *testing.T) {
	t.Parallel()
	pack, e, err := compilePoliciesFromSource(map[string]string{
		"check": `package mypolicies
deny[msg] { msg := "fail" }
`,
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	a := NewAnalyzer(pack, e)
	if name := a.Name(); name != "mypolicies" {
		t.Errorf("expected Name() = %q, got %q", "mypolicies", name)
	}
}

func TestAnalyzer_Remediate(t *testing.T) {
	t.Parallel()
	pack, e, err := compilePoliciesFromSource(map[string]string{
		"check": `package test
deny[msg] { msg := "fail" }
`,
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	a := NewAnalyzer(pack, e)
	resp, err := a.Remediate(plugin.AnalyzerResource{
		URN:        resource.URN("urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket"),
		Type:       tokens.Type("aws:s3/bucket:Bucket"),
		Name:       "bucket",
		Properties: resource.NewPropertyMapFromMap(map[string]any{"acl": "public-read"}),
	})
	if err != nil {
		t.Fatalf("Remediate returned error: %v", err)
	}
	if len(resp.Remediations) != 0 {
		t.Errorf("expected no remediations, got %d", len(resp.Remediations))
	}
}

func TestAnalyzer_GetPluginInfo(t *testing.T) {
	t.Parallel()

	// Save and restore the global VersionString.
	origVersion := VersionString
	t.Cleanup(func() { VersionString = origVersion })

	pack, e, err := compilePoliciesFromSource(map[string]string{
		"check": `package test
deny[msg] { msg := "fail" }
`,
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	a := NewAnalyzer(pack, e)

	VersionString = "1.2.3"
	info, err := a.GetPluginInfo()
	if err != nil {
		t.Fatalf("GetPluginInfo returned error: %v", err)
	}
	if info.Version == nil {
		t.Fatal("expected non-nil Version")
	}
	if info.Version.String() != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %s", info.Version.String())
	}

	VersionString = "not-a-version"
	_, err = a.GetPluginInfo()
	if err == nil {
		t.Error("expected error for invalid version string")
	}
}

func TestAnalyzer_CancelAndClose(t *testing.T) {
	t.Parallel()
	pack, e, err := compilePoliciesFromSource(map[string]string{
		"check": `package test
deny[msg] { msg := "fail" }
`,
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	a := NewAnalyzer(pack, e)

	if err := a.Cancel(context.Background()); err != nil {
		t.Errorf("Cancel returned error: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestAnalyzer_GetAnalyzerInfo_ReportsPolicyTypes(t *testing.T) {
	t.Parallel()
	regoSource := `
package test_types

deny[msg] {
    msg := "resource rule"
}

stack_deny[msg] {
    msg := "stack rule"
}

warn[msg] {
    msg := "resource warning"
}

stack_warn[msg] {
    msg := "stack warning"
}
`
	pack, e, err := compilePoliciesFromSource(map[string]string{
		"types": regoSource,
	})
	if err != nil {
		t.Fatalf("failed to compile policy: %v", err)
	}

	a := NewAnalyzer(pack, e)

	info, err := a.GetAnalyzerInfo()
	if err != nil {
		t.Fatalf("GetAnalyzerInfo returned error: %v", err)
	}

	if len(info.Policies) != 4 {
		t.Fatalf("expected 4 policies, got %d", len(info.Policies))
	}

	// Build a map for easy lookup.
	policyMap := make(map[string]plugin.AnalyzerPolicyInfo)
	for _, p := range info.Policies {
		policyMap[p.Name] = p
	}

	// Resource-level rules should be AnalyzerPolicyTypeResource.
	if p, ok := policyMap["deny"]; ok {
		if p.Type != plugin.AnalyzerPolicyTypeResource {
			t.Errorf("deny: expected AnalyzerPolicyTypeResource, got %v", p.Type)
		}
	} else {
		t.Error("deny rule not found in policy info")
	}

	if p, ok := policyMap["warn"]; ok {
		if p.Type != plugin.AnalyzerPolicyTypeResource {
			t.Errorf("warn: expected AnalyzerPolicyTypeResource, got %v", p.Type)
		}
	} else {
		t.Error("warn rule not found in policy info")
	}

	// Stack-level rules should be AnalyzerPolicyTypeStack.
	if p, ok := policyMap["stack_deny"]; ok {
		if p.Type != plugin.AnalyzerPolicyTypeStack {
			t.Errorf("stack_deny: expected AnalyzerPolicyTypeStack, got %v", p.Type)
		}
	} else {
		t.Error("stack_deny rule not found in policy info")
	}

	if p, ok := policyMap["stack_warn"]; ok {
		if p.Type != plugin.AnalyzerPolicyTypeStack {
			t.Errorf("stack_warn: expected AnalyzerPolicyTypeStack, got %v", p.Type)
		}
	} else {
		t.Error("stack_warn rule not found in policy info")
	}
}
