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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
)

// --- Configure tests ---

// TestConfigure_StoresConfig verifies that Configure stores the policy config
// and subsequent evaluations use it.
func TestConfigure_StoresConfig(t *testing.T) {
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

	// Verify config is stored.
	if a.policyConfig == nil {
		t.Fatal("expected policyConfig to be set")
	}
	if a.policyConfig["deny"].Properties["maxInstanceSize"] != "t3.xlarge" {
		t.Errorf("expected maxInstanceSize = t3.xlarge, got %v",
			a.policyConfig["deny"].Properties["maxInstanceSize"])
	}
}

// TestConfigure_RejectsInvalidEnforcementLevel verifies that Configure returns
// an error when given an unrecognized enforcement level string.
func TestConfigure_RejectsInvalidEnforcementLevel(t *testing.T) {
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
}

// --- Config passthrough to Rego via data.config ---

// TestConfig_DataConfigAccessible verifies that config properties are available
// to Rego rules via data.config.<policy_name>.<key>.
func TestConfig_DataConfigAccessible(t *testing.T) {
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
}

// TestConfig_DataConfigMultiplePolicies verifies that config properties for
// different policies are isolated under their respective policy names.
func TestConfig_DataConfigMultiplePolicies(t *testing.T) {
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
}

// TestConfig_DataConfigWithStackRule verifies that config works with stack-level rules.
func TestConfig_DataConfigWithStackRule(t *testing.T) {
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
}

// TestConfig_NilConfigHandledGracefully verifies that nil config doesn't break evaluation.
func TestConfig_NilConfigHandledGracefully(t *testing.T) {
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
}

// TestConfig_MissingConfigHandledGracefully verifies that when a rule references
// data.config but no config is provided, OPA evaluation doesn't fail — the rule
// simply doesn't fire (undefined data path).
func TestConfig_MissingConfigHandledGracefully(t *testing.T) {
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
}

// --- Enforcement level override tests ---

// TestConfig_EnforcementOverride_DenyToAdvisory verifies that a mandatory (deny)
// rule can be downgraded to advisory via config.
func TestConfig_EnforcementOverride_DenyToAdvisory(t *testing.T) {
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
}

// TestConfig_EnforcementOverride_WarnToMandatory verifies that an advisory (warn)
// rule can be promoted to mandatory via config.
func TestConfig_EnforcementOverride_WarnToMandatory(t *testing.T) {
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
}

// TestConfig_EnforcementOverride_Disabled verifies that a disabled rule is
// skipped during evaluation and produces no diagnostics.
func TestConfig_EnforcementOverride_Disabled(t *testing.T) {
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
}

// TestConfig_EnforcementOverride_DisabledStackRule verifies that a disabled
// stack rule is skipped.
func TestConfig_EnforcementOverride_DisabledStackRule(t *testing.T) {
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
}

// TestConfig_EnforcementOverride_PartialDisable verifies that disabling one rule
// doesn't affect other rules.
func TestConfig_EnforcementOverride_PartialDisable(t *testing.T) {
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
}

// --- Config + enforcement combined ---

// TestConfig_CombinedConfigAndEnforcement verifies that both config properties
// and enforcement level overrides work together.
func TestConfig_CombinedConfigAndEnforcement(t *testing.T) {
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

// --- buildDiagnostics tests ---

// TestBuildDiagnostics_NoConfig verifies that buildDiagnostics works with nil config.
func TestBuildDiagnostics_NoConfig(t *testing.T) {
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
}

// TestBuildDiagnostics_DisabledFiltered verifies that disabled results are omitted.
func TestBuildDiagnostics_DisabledFiltered(t *testing.T) {
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
}

// --- Config schema loading tests ---

// TestLoadConfigSchemas_ValidFile verifies loading a well-formed config-schema.json.
func TestLoadConfigSchemas_ValidFile(t *testing.T) {
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
}

// TestLoadConfigSchemas_MissingFile verifies that missing schema file returns empty map.
func TestLoadConfigSchemas_MissingFile(t *testing.T) {
	schemas := loadConfigSchemas(t.TempDir())
	if len(schemas) != 0 {
		t.Errorf("expected 0 schemas for missing file, got %d", len(schemas))
	}
}

// TestLoadConfigSchemas_MalformedFile verifies that malformed JSON returns empty map.
func TestLoadConfigSchemas_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config-schema.json"), []byte("{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	schemas := loadConfigSchemas(dir)
	if len(schemas) != 0 {
		t.Errorf("expected 0 schemas for malformed file, got %d", len(schemas))
	}
}

// --- GetAnalyzerInfo tests ---

// TestGetAnalyzerInfo_IncludesConfigSchema verifies that config schemas from
// config-schema.json appear in GetAnalyzerInfo output.
func TestGetAnalyzerInfo_IncludesConfigSchema(t *testing.T) {
	dir := t.TempDir()

	// Write a policy.
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

	// Write config schema.
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

	// Find the deny_size policy — it should have a config schema.
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

// --- buildConfigStore tests ---

// TestBuildConfigStore_NilConfig returns nil store.
func TestBuildConfigStore_NilConfig(t *testing.T) {
	store := buildConfigStore(nil)
	if store != nil {
		t.Error("expected nil store for nil config")
	}
}

// TestBuildConfigStore_EmptyConfig returns nil store.
func TestBuildConfigStore_EmptyConfig(t *testing.T) {
	store := buildConfigStore(map[string]plugin.AnalyzerPolicyConfig{})
	if store != nil {
		t.Error("expected nil store for empty config")
	}
}

// TestBuildConfigStore_OnlyEnforcement returns nil store (no properties).
func TestBuildConfigStore_OnlyEnforcement(t *testing.T) {
	config := map[string]plugin.AnalyzerPolicyConfig{
		"deny": {EnforcementLevel: apitype.Advisory},
	}
	store := buildConfigStore(config)
	if store != nil {
		t.Error("expected nil store when only enforcement level is set")
	}
}

// TestBuildConfigStore_WithProperties returns non-nil store.
func TestBuildConfigStore_WithProperties(t *testing.T) {
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
}

// --- "all" pack-wide enforcement override tests ---

// TestConfig_AllOverride_AppliesToAllRules verifies that the "all" config key
// sets a pack-wide default enforcement level for all rules.
func TestConfig_AllOverride_AppliesToAllRules(t *testing.T) {
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
}

// TestConfig_AllOverride_PolicySpecificTakesPrecedence verifies that a
// policy-specific override takes precedence over the "all" default.
func TestConfig_AllOverride_PolicySpecificTakesPrecedence(t *testing.T) {
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
}

// TestConfig_AllOverride_DisabledSkipsAll verifies that "all" with disabled
// enforcement skips all rules during evaluation.
func TestConfig_AllOverride_DisabledSkipsAll(t *testing.T) {
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
}

// TestConfig_AllOverride_PolicySpecificEnableOverridesAllDisabled verifies that
// a policy-specific override can re-enable a rule when "all" is disabled.
func TestConfig_AllOverride_PolicySpecificEnableOverridesAllDisabled(t *testing.T) {
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
}

// TestConfiguredEnforcementLevel_Precedence verifies the helper function
// returns the correct precedence: policy-specific > "all" > empty.
func TestConfiguredEnforcementLevel_Precedence(t *testing.T) {
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
