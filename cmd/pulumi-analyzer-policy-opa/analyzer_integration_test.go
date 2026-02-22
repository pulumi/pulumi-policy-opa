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
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
)

// TestAnalyzer_Analyze_PassesMetadata tests the full round-trip: Analyze() builds the
// enriched input and evaluates a Rego policy that references metadata fields.
func TestAnalyzer_Analyze_PassesMetadata(t *testing.T) {
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

	// Test 1: Production resource without protect — should produce a violation.
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

	// Test 2: Production resource with protect — should pass cleanly.
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

	// Test 3: Staging resource without protect — should pass (no "production" in URN).
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
}

// TestAnalyzer_Analyze_BackwardCompatible verifies that policies using only
// input properties (the pre-issue-10 pattern) continue to work correctly.
func TestAnalyzer_Analyze_BackwardCompatible(t *testing.T) {
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
}

// TestAnalyzer_Analyze_RegoV0Compatible verifies that policies written in Rego v0
// syntax (deny[msg] { ... }) compile and evaluate correctly.
func TestAnalyzer_Analyze_RegoV0Compatible(t *testing.T) {
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

	for _, module := range compiler.Modules {
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
			if denyRulePrefix.MatchString(ruleName) {
				level = mandatoryRule
			} else if warnRulePrefix.MatchString(ruleName) {
				level = advisoryRule
			} else {
				continue
			}
			if !existing[ruleName] {
				existing[ruleName] = true
				policies = append(policies, &policyRule{
					Name:  ruleName,
					Level: level,
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
