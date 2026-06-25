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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
)

func TestConfigure(t *testing.T) {
	t.Parallel()

	t.Run("StoresConfig", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    max_size := data.config.deny.maxInstanceSize
    input.instanceType == max_size
    msg := sprintf("instance type '%s' is not allowed", [input.instanceType])
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				Properties: map[string]any{
					"maxInstanceSize": "t3.xlarge",
				},
			},
		}
		if err := a.Configure(config); err != nil {
			t.Fatalf("Configure failed: %v", err)
		}

		if a.policyConfig == nil {
			t.Fatal("expected policyConfig to be set")
		}
		if a.policyConfig["deny"].Properties["maxInstanceSize"] != "t3.xlarge" {
			t.Errorf("expected maxInstanceSize = t3.xlarge, got %v",
				a.policyConfig["deny"].Properties["maxInstanceSize"])
		}
	})

	t.Run("RejectsInvalidEnforcementLevel", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    msg := "fail"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				EnforcementLevel: "bogus",
			},
		}
		if err := a.Configure(config); err == nil {
			t.Fatal("expected Configure to reject invalid enforcement level")
		}
	})
}

func TestConfig_DataConfig(t *testing.T) {
	t.Parallel()

	t.Run("Accessible", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    max := data.config.deny.maxBuckets
    input.bucketCount > max
    msg := sprintf("too many buckets: %d > %d", [input.bucketCount, max])
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				Properties: map[string]any{
					"maxBuckets": float64(3),
				},
			},
		}

		// Should violate with 5 buckets (limit 3).
		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{"bucketCount": float64(5)}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(results))
		}
		if results[0].msg != "too many buckets: 5 > 3" {
			t.Errorf("unexpected message: %s", results[0].msg)
		}

		// Should pass with 2 buckets.
		results, err = e.evalPolicyPack(context.Background(), pack,
			map[string]any{"bucketCount": float64(2)}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 violations, got %d", len(results))
		}
	})

	t.Run("MultiplePolicies", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny_size[msg] {
    max := data.config.deny_size.maxSize
    input.size > max
    msg := sprintf("size %d exceeds max %d", [input.size, max])
}

deny_count[msg] {
    max := data.config.deny_count.maxCount
    input.count > max
    msg := sprintf("count %d exceeds max %d", [input.count, max])
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny_size": {
				Properties: map[string]any{
					"maxSize": float64(100),
				},
			},
			"deny_count": {
				Properties: map[string]any{
					"maxCount": float64(5),
				},
			},
		}

		// Input violates size but not count.
		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{"size": float64(200), "count": float64(3)}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(results))
		}
		if results[0].rule != "deny_size" {
			t.Errorf("expected deny_size violation, got %s", results[0].rule)
		}
	})

	t.Run("WithStackRule", func(t *testing.T) {
		t.Parallel()
		module := `
package test

stack_deny_too_many[msg] {
    max := data.config.stack_deny_too_many.maxResources
    count(input.resources) > max
    msg := sprintf("stack has %d resources, max %d", [count(input.resources), max])
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"stack_deny_too_many": {
				Properties: map[string]any{
					"maxResources": float64(2),
				},
			},
		}

		input := map[string]any{
			"resources": []any{
				map[string]any{"__name": "r1"},
				map[string]any{"__name": "r2"},
				map[string]any{"__name": "r3"},
			},
		}

		results, err := e.evalPolicyPack(context.Background(), pack, input, stackScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(results))
		}
	})

	t.Run("NilConfigGraceful", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    input.acl == "public"
    msg := "public access denied"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{"acl": "public"}, resourceScope, nil)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 violation, got %d", len(results))
		}
	})

	t.Run("MissingConfigGraceful", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    max := data.config.deny.maxBuckets
    input.count > max
    msg := "too many"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		// No config provided — rule should not fire since data.config.deny.maxBuckets is undefined.
		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{"count": float64(100)}, resourceScope, nil)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 violations when config is missing, got %d", len(results))
		}
	})
}

func TestConfig_EnforcementOverride(t *testing.T) {
	t.Parallel()

	t.Run("DenyToAdvisory", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    msg := "always fails"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				EnforcementLevel: apitype.Advisory,
			},
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}

		// The result itself still has the original level; the override is applied in buildDiagnostics.
		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
		if len(diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
		}
		if diagnostics[0].EnforcementLevel != apitype.Advisory {
			t.Errorf("expected advisory, got %s", diagnostics[0].EnforcementLevel)
		}
	})

	t.Run("WarnToMandatory", func(t *testing.T) {
		t.Parallel()
		module := `
package test

warn[msg] {
    msg := "always warns"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"warn": {
				EnforcementLevel: apitype.Mandatory,
			},
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}

		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
		if len(diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
		}
		if diagnostics[0].EnforcementLevel != apitype.Mandatory {
			t.Errorf("expected mandatory, got %s", diagnostics[0].EnforcementLevel)
		}
	})

	t.Run("Disabled", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny[msg] {
    msg := "should be skipped"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				EnforcementLevel: apitype.Disabled,
			},
		}

		// Disabled rules are skipped during evaluation.
		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results for disabled rule, got %d", len(results))
		}
	})

	t.Run("DisabledStackRule", func(t *testing.T) {
		t.Parallel()
		module := `
package test

stack_deny[msg] {
    msg := "should be skipped"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"stack_deny": {
				EnforcementLevel: apitype.Disabled,
			},
		}

		input := map[string]any{"resources": []any{}}
		results, err := e.evalPolicyPack(context.Background(), pack, input, stackScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results for disabled stack rule, got %d", len(results))
		}
	})

	t.Run("PartialDisable", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny_a[msg] {
    msg := "rule A"
}

deny_b[msg] {
    msg := "rule B"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny_a": {
				EnforcementLevel: apitype.Disabled,
			},
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}

		// Only deny_b should produce results.
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].rule != "deny_b" {
			t.Errorf("expected deny_b, got %s", results[0].rule)
		}
	})
}

func TestConfig_CombinedConfigAndEnforcement(t *testing.T) {
	t.Parallel()
	module := `
package test

deny_size[msg] {
    max := data.config.deny_size.maxSize
    input.size > max
    msg := sprintf("size %d exceeds %d", [input.size, max])
}
`
	dir := writeRegoFile(t, "policy.rego", module)
	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	config := map[string]plugin.AnalyzerPolicyConfig{
		"deny_size": {
			EnforcementLevel: apitype.Advisory,
			Properties: map[string]any{
				"maxSize": float64(50),
			},
		},
	}

	results, err := e.evalPolicyPack(context.Background(), pack,
		map[string]any{"size": float64(100)}, resourceScope, config)
	if err != nil {
		t.Fatalf("evalPolicyPack failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
	}
	if diagnostics[0].EnforcementLevel != apitype.Advisory {
		t.Errorf("expected advisory, got %s", diagnostics[0].EnforcementLevel)
	}
	if diagnostics[0].Message != "size 100 exceeds 50" {
		t.Errorf("unexpected message: %s", diagnostics[0].Message)
	}
}

func TestBuildDiagnostics(t *testing.T) {
	t.Parallel()

	t.Run("NoConfig", func(t *testing.T) {
		t.Parallel()
		results := []evalPolicyResult{
			{pack: "test", rule: "deny", msg: "fail", level: mandatoryRule},
			{pack: "test", rule: "warn", msg: "warning", level: advisoryRule},
		}

		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), nil)
		if len(diagnostics) != 2 {
			t.Fatalf("expected 2 diagnostics, got %d", len(diagnostics))
		}
		if diagnostics[0].EnforcementLevel != apitype.Mandatory {
			t.Errorf("expected mandatory for deny, got %s", diagnostics[0].EnforcementLevel)
		}
		if diagnostics[1].EnforcementLevel != apitype.Advisory {
			t.Errorf("expected advisory for warn, got %s", diagnostics[1].EnforcementLevel)
		}
	})

	t.Run("DisabledFiltered", func(t *testing.T) {
		t.Parallel()
		results := []evalPolicyResult{
			{pack: "test", rule: "deny_a", msg: "fail A", level: mandatoryRule},
			{pack: "test", rule: "deny_b", msg: "fail B", level: mandatoryRule},
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny_a": {EnforcementLevel: apitype.Disabled},
		}

		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
		if len(diagnostics) != 1 {
			t.Fatalf("expected 1 diagnostic (deny_a disabled), got %d", len(diagnostics))
		}
		if diagnostics[0].PolicyName != "deny_b" {
			t.Errorf("expected deny_b, got %s", diagnostics[0].PolicyName)
		}
	})
}

func TestLoadConfigSchemas(t *testing.T) {
	t.Parallel()

	t.Run("ValidFile", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		schema := map[string]any{
			"deny_size": map[string]any{
				"properties": map[string]any{
					"maxSize": map[string]any{
						"type":    "number",
						"default": float64(100),
					},
				},
				"required": []any{"maxSize"},
			},
		}
		data, _ := json.Marshal(schema)
		if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		schemas := loadConfigSchemas(dir)
		if len(schemas) != 1 {
			t.Fatalf("expected 1 schema, got %d", len(schemas))
		}

		s, ok := schemas["deny_size"]
		if !ok {
			t.Fatal("expected deny_size schema")
		}
		if len(s.Properties) != 1 {
			t.Errorf("expected 1 property, got %d", len(s.Properties))
		}
		if len(s.Required) != 1 || s.Required[0] != "maxSize" {
			t.Errorf("expected required=[maxSize], got %v", s.Required)
		}
	})

	t.Run("MissingFile", func(t *testing.T) {
		t.Parallel()
		schemas := loadConfigSchemas(t.TempDir())
		if len(schemas) != 0 {
			t.Errorf("expected 0 schemas for missing file, got %d", len(schemas))
		}
	})

	t.Run("MalformedFile", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), []byte("{invalid"), 0o644); err != nil {
			t.Fatal(err)
		}
		schemas := loadConfigSchemas(dir)
		if len(schemas) != 0 {
			t.Errorf("expected 0 schemas for malformed file, got %d", len(schemas))
		}
	})
}

func TestGetAnalyzerInfo_IncludesConfigSchema(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	module := `
package test

deny_size[msg] {
    msg := "too big"
}

warn_tags[msg] {
    msg := "no tags"
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(module), 0o644); err != nil {
		t.Fatal(err)
	}

	schema := map[string]any{
		"deny_size": map[string]any{
			"properties": map[string]any{
				"maxSize": map[string]any{"type": "number"},
			},
		},
	}
	data, _ := json.Marshal(schema)
	if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	a := NewAnalyzer(pack, e)
	info, err := a.GetAnalyzerInfo()
	if err != nil {
		t.Fatalf("GetAnalyzerInfo failed: %v", err)
	}

	if !info.SupportsConfig {
		t.Error("expected SupportsConfig = true")
	}

	var foundSchema bool
	for _, pol := range info.Policies {
		if pol.Name == "deny_size" {
			if pol.ConfigSchema == nil {
				t.Error("expected deny_size to have a config schema")
			} else {
				foundSchema = true
				if _, ok := pol.ConfigSchema.Properties["maxSize"]; !ok {
					t.Error("expected maxSize in config schema properties")
				}
			}
		}
		if pol.Name == "warn_tags" {
			if pol.ConfigSchema != nil {
				t.Error("expected warn_tags to have no config schema")
			}
		}
	}
	if !foundSchema {
		t.Error("deny_size policy not found in info")
	}
}

func TestBuildConfigStore(t *testing.T) {
	t.Parallel()

	t.Run("NilConfig", func(t *testing.T) {
		t.Parallel()
		store := buildConfigStore(nil)
		if store != nil {
			t.Error("expected nil store for nil config")
		}
	})

	t.Run("EmptyConfig", func(t *testing.T) {
		t.Parallel()
		store := buildConfigStore(map[string]plugin.AnalyzerPolicyConfig{})
		if store != nil {
			t.Error("expected nil store for empty config")
		}
	})

	t.Run("OnlyEnforcement", func(t *testing.T) {
		t.Parallel()
		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {EnforcementLevel: apitype.Advisory},
		}
		store := buildConfigStore(config)
		if store != nil {
			t.Error("expected nil store when only enforcement level is set")
		}
	})

	t.Run("WithProperties", func(t *testing.T) {
		t.Parallel()
		config := map[string]plugin.AnalyzerPolicyConfig{
			"deny": {
				Properties: map[string]any{
					"maxSize": float64(100),
				},
			},
		}
		store := buildConfigStore(config)
		if store == nil {
			t.Error("expected non-nil store when properties are set")
		}
	})
}

func TestConfig_AllOverride(t *testing.T) {
	t.Parallel()

	t.Run("AppliesToAllRules", func(t *testing.T) {
		t.Parallel()
		results := []evalPolicyResult{
			{pack: "test", rule: "deny_a", msg: "fail A", level: mandatoryRule},
			{pack: "test", rule: "deny_b", msg: "fail B", level: mandatoryRule},
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"all": {EnforcementLevel: apitype.Advisory},
		}

		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
		if len(diagnostics) != 2 {
			t.Fatalf("expected 2 diagnostics, got %d", len(diagnostics))
		}
		for _, d := range diagnostics {
			if d.EnforcementLevel != apitype.Advisory {
				t.Errorf("expected advisory for %s, got %s", d.PolicyName, d.EnforcementLevel)
			}
		}
	})

	t.Run("PolicySpecificTakesPrecedence", func(t *testing.T) {
		t.Parallel()
		results := []evalPolicyResult{
			{pack: "test", rule: "deny_a", msg: "fail A", level: mandatoryRule},
			{pack: "test", rule: "deny_b", msg: "fail B", level: mandatoryRule},
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"all":    {EnforcementLevel: apitype.Advisory},
			"deny_a": {EnforcementLevel: apitype.Mandatory},
		}

		diagnostics := buildDiagnostics(results, resource.URN("urn:pulumi:s::p::t::r"), config)
		if len(diagnostics) != 2 {
			t.Fatalf("expected 2 diagnostics, got %d", len(diagnostics))
		}
		for _, d := range diagnostics {
			if d.PolicyName == "deny_a" && d.EnforcementLevel != apitype.Mandatory {
				t.Errorf("expected mandatory for deny_a (policy-specific), got %s", d.EnforcementLevel)
			}
			if d.PolicyName == "deny_b" && d.EnforcementLevel != apitype.Advisory {
				t.Errorf("expected advisory for deny_b (from 'all'), got %s", d.EnforcementLevel)
			}
		}
	})

	t.Run("DisabledSkipsAll", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny_a[msg] {
    msg := "rule A"
}

deny_b[msg] {
    msg := "rule B"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"all": {EnforcementLevel: apitype.Disabled},
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results when all disabled, got %d", len(results))
		}
	})

	t.Run("PolicySpecificEnableOverridesAllDisabled", func(t *testing.T) {
		t.Parallel()
		module := `
package test

deny_a[msg] {
    msg := "rule A"
}

deny_b[msg] {
    msg := "rule B"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		config := map[string]plugin.AnalyzerPolicyConfig{
			"all":    {EnforcementLevel: apitype.Disabled},
			"deny_b": {EnforcementLevel: apitype.Mandatory},
		}

		results, err := e.evalPolicyPack(context.Background(), pack,
			map[string]any{}, resourceScope, config)
		if err != nil {
			t.Fatalf("evalPolicyPack failed: %v", err)
		}

		// Only deny_b should be evaluated (deny_a disabled via "all").
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].rule != "deny_b" {
			t.Errorf("expected deny_b, got %s", results[0].rule)
		}
	})
}

func TestConfiguredEnforcementLevel_Precedence(t *testing.T) {
	t.Parallel()

	// Nil config returns empty.
	if level := configuredEnforcementLevel(nil, "deny"); level != "" {
		t.Errorf("expected empty for nil config, got %s", level)
	}

	// No matching key returns empty.
	config := map[string]plugin.AnalyzerPolicyConfig{
		"other": {EnforcementLevel: apitype.Advisory},
	}
	if level := configuredEnforcementLevel(config, "deny"); level != "" {
		t.Errorf("expected empty for non-matching key, got %s", level)
	}

	// "all" applies when no policy-specific key.
	config = map[string]plugin.AnalyzerPolicyConfig{
		"all": {EnforcementLevel: apitype.Advisory},
	}
	if level := configuredEnforcementLevel(config, "deny"); level != apitype.Advisory {
		t.Errorf("expected advisory from 'all', got %s", level)
	}

	// Policy-specific takes precedence over "all".
	config = map[string]plugin.AnalyzerPolicyConfig{
		"all":  {EnforcementLevel: apitype.Advisory},
		"deny": {EnforcementLevel: apitype.Mandatory},
	}
	if level := configuredEnforcementLevel(config, "deny"); level != apitype.Mandatory {
		t.Errorf("expected mandatory from policy-specific, got %s", level)
	}
}

// captureStderr runs fn while capturing os.Stderr output and returns the captured string.
// Not safe for parallel use since it mutates the global os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = origStderr

	out, _ := io.ReadAll(r)
	return string(out)
}

func TestWarnMissingConfig(t *testing.T) {
	// These tests capture os.Stderr so they must not run in parallel with each other.

	t.Run("WarnsWhenSchemaButNoConfig", func(t *testing.T) {
		dir := t.TempDir()

		module := `
package test

deny_size[msg] {
    max := data.config.deny_size.maxSize
    input.size > max
    msg := "too big"
}
`
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(module), 0o644); err != nil {
			t.Fatal(err)
		}

		schema := map[string]any{
			"deny_size": map[string]any{
				"properties": map[string]any{
					"maxSize": map[string]any{"type": "number"},
				},
			},
		}
		data, _ := json.Marshal(schema)
		if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)
		// No Configure() call — policyConfig is nil.

		stderr := captureStderr(t, func() {
			_, _ = a.Analyze(plugin.AnalyzerResource{
				Type:       "test:index:Resource",
				Properties: resource.NewPropertyMapFromMap(map[string]any{"size": float64(200)}),
			})
		})

		if !strings.Contains(stderr, "warning[opa/missing-config]") {
			t.Errorf("expected stable diagnostic code, got: %q", stderr)
		}
		if !strings.Contains(stderr, "deny_size") {
			t.Errorf("expected warning mentioning deny_size, got: %q", stderr)
		}
		if !strings.Contains(stderr, "no configuration was provided") {
			t.Errorf("expected warning about missing config, got: %q", stderr)
		}
	})

	t.Run("NoWarningWhenConfigProvided", func(t *testing.T) {
		dir := t.TempDir()

		module := `
package test

deny_size[msg] {
    max := data.config.deny_size.maxSize
    input.size > max
    msg := "too big"
}
`
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(module), 0o644); err != nil {
			t.Fatal(err)
		}

		schema := map[string]any{
			"deny_size": map[string]any{
				"properties": map[string]any{
					"maxSize": map[string]any{"type": "number"},
				},
			},
		}
		data, _ := json.Marshal(schema)
		if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)
		_ = a.Configure(map[string]plugin.AnalyzerPolicyConfig{
			"deny_size": {
				Properties: map[string]any{"maxSize": float64(100)},
			},
		})

		stderr := captureStderr(t, func() {
			_, _ = a.Analyze(plugin.AnalyzerResource{
				Type:       "test:index:Resource",
				Properties: resource.NewPropertyMapFromMap(map[string]any{"size": float64(200)}),
			})
		})

		if stderr != "" {
			t.Errorf("expected no warnings, got: %q", stderr)
		}
	})

	t.Run("WarnsOnlyOnce", func(t *testing.T) {
		dir := t.TempDir()

		module := `
package test

deny_size[msg] {
    max := data.config.deny_size.maxSize
    input.size > max
    msg := "too big"
}
`
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(module), 0o644); err != nil {
			t.Fatal(err)
		}

		schema := map[string]any{
			"deny_size": map[string]any{
				"properties": map[string]any{
					"maxSize": map[string]any{"type": "number"},
				},
			},
		}
		data, _ := json.Marshal(schema)
		if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)

		// First call should warn.
		stderr1 := captureStderr(t, func() {
			_, _ = a.Analyze(plugin.AnalyzerResource{
				Type:       "test:index:Resource",
				Properties: resource.NewPropertyMapFromMap(map[string]any{"size": float64(200)}),
			})
		})
		if !strings.Contains(stderr1, "deny_size") {
			t.Fatalf("expected warning on first call, got: %q", stderr1)
		}

		// Second call should not warn again.
		stderr2 := captureStderr(t, func() {
			_, _ = a.Analyze(plugin.AnalyzerResource{
				Type:       "test:index:Resource",
				Properties: resource.NewPropertyMapFromMap(map[string]any{"size": float64(300)}),
			})
		})
		if stderr2 != "" {
			t.Errorf("expected no warning on second call, got: %q", stderr2)
		}
	})

	t.Run("NoWarningWithoutSchema", func(t *testing.T) {
		// Rule references data.config but has no config-schema.json — no warning expected.
		module := `
package test

deny[msg] {
    max := data.config.deny.maxBuckets
    input.count > max
    msg := "too many"
}
`
		dir := writeRegoFile(t, "policy.rego", module)
		pack, e, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		a := NewAnalyzer(pack, e).(*analyzer)

		stderr := captureStderr(t, func() {
			_, _ = a.Analyze(plugin.AnalyzerResource{
				Type:       "test:index:Resource",
				Properties: resource.NewPropertyMapFromMap(map[string]any{"count": float64(100)}),
			})
		})

		if stderr != "" {
			t.Errorf("expected no warning without schema, got: %q", stderr)
		}
	})
}
