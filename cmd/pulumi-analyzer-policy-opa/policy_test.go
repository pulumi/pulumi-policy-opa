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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findRule searches a policyPack's policies for a rule with the given name.
func findRule(pack *policyPack, name string) *policyRule {
	for _, p := range pack.Policies {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func TestLoadPolicies(t *testing.T) {
	t.Parallel()

	t.Run("StackDenyRule", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

stack_deny[msg] {
    count(input.resources) > 10
    msg := "too many resources"
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		rule := findRule(pack, "stack_deny")
		if rule == nil {
			t.Fatal("expected stack_deny rule to be loaded")
		}
		if rule.Level != mandatoryRule {
			t.Errorf("expected mandatory level, got %v", rule.Level)
		}
		if rule.Scope != stackScope {
			t.Errorf("expected stack scope, got %v", rule.Scope)
		}
	})

	t.Run("StackWarnRule", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

stack_warn[msg] {
    count(input.resources) > 5
    msg := "many resources in stack"
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		rule := findRule(pack, "stack_warn")
		if rule == nil {
			t.Fatal("expected stack_warn rule to be loaded")
		}
		if rule.Level != advisoryRule {
			t.Errorf("expected advisory level, got %v", rule.Level)
		}
		if rule.Scope != stackScope {
			t.Errorf("expected stack scope, got %v", rule.Scope)
		}
	})

	t.Run("StackDenySuffixRule", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

stack_deny_no_public_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    r.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not be public", [r.__name])
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		rule := findRule(pack, "stack_deny_no_public_buckets")
		if rule == nil {
			t.Fatal("expected stack_deny_no_public_buckets rule to be loaded")
		}
		if rule.Level != mandatoryRule {
			t.Errorf("expected mandatory level, got %v", rule.Level)
		}
		if rule.Scope != stackScope {
			t.Errorf("expected stack scope, got %v", rule.Scope)
		}
	})

	t.Run("MixedRules", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}

stack_deny[msg] {
    count(input.resources) > 10
    msg := "too many resources"
}

warn[msg] {
    not input.tags
    msg := "resource should have tags"
}

stack_warn[msg] {
    count(input.resources) > 5
    msg := "consider reducing resource count"
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		// Verify we have all 4 rules.
		if len(pack.Policies) != 4 {
			t.Fatalf("expected 4 policies, got %d", len(pack.Policies))
		}

		// Check resource-level deny rule.
		denyRule := findRule(pack, "deny")
		if denyRule == nil {
			t.Fatal("expected deny rule to be loaded")
		}
		if denyRule.Level != mandatoryRule {
			t.Errorf("deny: expected mandatory level, got %v", denyRule.Level)
		}
		if denyRule.Scope != resourceScope {
			t.Errorf("deny: expected resource scope, got %v", denyRule.Scope)
		}

		// Check stack-level deny rule.
		stackDenyRule := findRule(pack, "stack_deny")
		if stackDenyRule == nil {
			t.Fatal("expected stack_deny rule to be loaded")
		}
		if stackDenyRule.Level != mandatoryRule {
			t.Errorf("stack_deny: expected mandatory level, got %v", stackDenyRule.Level)
		}
		if stackDenyRule.Scope != stackScope {
			t.Errorf("stack_deny: expected stack scope, got %v", stackDenyRule.Scope)
		}

		// Check resource-level warn rule.
		warnRule := findRule(pack, "warn")
		if warnRule == nil {
			t.Fatal("expected warn rule to be loaded")
		}
		if warnRule.Level != advisoryRule {
			t.Errorf("warn: expected advisory level, got %v", warnRule.Level)
		}
		if warnRule.Scope != resourceScope {
			t.Errorf("warn: expected resource scope, got %v", warnRule.Scope)
		}

		// Check stack-level warn rule.
		stackWarnRule := findRule(pack, "stack_warn")
		if stackWarnRule == nil {
			t.Fatal("expected stack_warn rule to be loaded")
		}
		if stackWarnRule.Level != advisoryRule {
			t.Errorf("stack_warn: expected advisory level, got %v", stackWarnRule.Level)
		}
		if stackWarnRule.Scope != stackScope {
			t.Errorf("stack_warn: expected stack scope, got %v", stackWarnRule.Scope)
		}
	})

	t.Run("StackViolationRule", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

stack_violation[msg] {
    count(input.resources) > 10
    msg := "too many resources in stack"
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		rule := findRule(pack, "stack_violation")
		if rule == nil {
			t.Fatal("expected stack_violation rule to be loaded")
		}
		if rule.Level != mandatoryRule {
			t.Errorf("expected mandatory level, got %v", rule.Level)
		}
		if rule.Scope != stackScope {
			t.Errorf("expected stack scope, got %v", rule.Scope)
		}
	})

	t.Run("RuleNameWithDigits", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test

deny_s3_check[msg] {
    msg := "s3 check"
}

warn_ec2_check[msg] {
    msg := "ec2 check"
}

stack_deny_s3_limit[msg] {
    msg := "s3 limit"
}

stack_warn_rds_count[msg] {
    msg := "rds count"
}

violation_r53_check[msg] {
    msg := "r53 check"
}

stack_violation_3bucket_check[msg] {
    msg := "3bucket check"
}
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}

		tests := []struct {
			name  string
			level enforcementLevel
			scope policyScope
		}{
			{"deny_s3_check", mandatoryRule, resourceScope},
			{"warn_ec2_check", advisoryRule, resourceScope},
			{"stack_deny_s3_limit", mandatoryRule, stackScope},
			{"stack_warn_rds_count", advisoryRule, stackScope},
			{"violation_r53_check", mandatoryRule, resourceScope},
			{"stack_violation_3bucket_check", mandatoryRule, stackScope},
		}

		for _, tc := range tests {
			rule := findRule(pack, tc.name)
			if rule == nil {
				t.Errorf("expected rule %q to be loaded", tc.name)
				continue
			}
			if rule.Level != tc.level {
				t.Errorf("%s: expected level %v, got %v", tc.name, tc.level, rule.Level)
			}
			if rule.Scope != tc.scope {
				t.Errorf("%s: expected scope %v, got %v", tc.name, tc.scope, rule.Scope)
			}
		}
	})
}

// TestLoadPolicies_RuleAnnotations verifies that OPA METADATA annotations on
// rules populate DisplayName, Description, and Message on the loaded policy.
func TestLoadPolicies_RuleAnnotations(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
package test

# METADATA
# title: No Public Buckets
# description: S3 buckets must not use public-read ACLs.
# custom:
#   message: Bucket has a public ACL
deny_no_public[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`)
	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	rule := findRule(pack, "deny_no_public")
	if rule == nil {
		t.Fatal("expected deny_no_public rule to be loaded")
	}
	if rule.DisplayName != "No Public Buckets" {
		t.Errorf("expected DisplayName = %q, got %q", "No Public Buckets", rule.DisplayName)
	}
	if rule.Description != "S3 buckets must not use public-read ACLs." {
		t.Errorf("expected Description = %q, got %q", "S3 buckets must not use public-read ACLs.", rule.Description)
	}
	if rule.Message != "Bucket has a public ACL" {
		t.Errorf("expected Message = %q, got %q", "Bucket has a public ACL", rule.Message)
	}
}

// TestLoadPolicies_RuleAnnotationsPartial verifies that partial annotations work—
// e.g., only title is set, Description and Message remain empty.
func TestLoadPolicies_RuleAnnotationsPartial(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
package test

# METADATA
# title: Encryption Check
deny_encryption[msg] {
    not input.encryption
    msg := "encryption required"
}
`)
	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	rule := findRule(pack, "deny_encryption")
	if rule == nil {
		t.Fatal("expected deny_encryption rule to be loaded")
	}
	if rule.DisplayName != "Encryption Check" {
		t.Errorf("expected DisplayName = %q, got %q", "Encryption Check", rule.DisplayName)
	}
	if rule.Description != "" {
		t.Errorf("expected empty Description, got %q", rule.Description)
	}
	if rule.Message != "" {
		t.Errorf("expected empty Message, got %q", rule.Message)
	}
}

// TestLoadPolicies_NoAnnotations verifies that rules without annotations have
// empty Description/Message and DisplayName falls back to the module name.
func TestLoadPolicies_NoAnnotations(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
package test

deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`)
	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	rule := findRule(pack, "deny")
	if rule == nil {
		t.Fatal("expected deny rule to be loaded")
	}
	if rule.DisplayName != "policy" {
		t.Errorf("expected DisplayName = %q (module name), got %q", "policy", rule.DisplayName)
	}
	if rule.Description != "" {
		t.Errorf("expected empty Description, got %q", rule.Description)
	}
	if rule.Message != "" {
		t.Errorf("expected empty Message, got %q", rule.Message)
	}
}

// TestLoadPolicies_PackageAnnotations verifies that a package-level METADATA
// annotation populates the policyPack.DisplayName.
func TestLoadPolicies_PackageAnnotations(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
# METADATA
# scope: package
# title: AWS Security Policies
package test

deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`)
	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	if pack.DisplayName != "AWS Security Policies" {
		t.Errorf("expected pack DisplayName = %q, got %q", "AWS Security Policies", pack.DisplayName)
	}
}

// TestLoadPolicies_NoPackageAnnotation verifies that without a package-level
// annotation, policyPack.DisplayName is empty.
func TestLoadPolicies_NoPackageAnnotation(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
package test

deny[msg] {
    msg := "fail"
}
`)
	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	if pack.DisplayName != "" {
		t.Errorf("expected empty pack DisplayName, got %q", pack.DisplayName)
	}
}

// TestGetAnalyzerInfo_IncludesAnnotations verifies that rule annotations flow
// through to GetAnalyzerInfo policy metadata.
func TestGetAnalyzerInfo_IncludesAnnotations(t *testing.T) {
	dir := writeRegoFile(t, "policy.rego", `
# METADATA
# scope: package
# title: My Policy Pack
package test

# METADATA
# title: No Public Access
# description: Denies resources with public ACLs.
# custom:
#   message: Resource has public access
deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`)
	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}

	a := NewAnalyzer(pack, e)
	info, err := a.GetAnalyzerInfo()
	if err != nil {
		t.Fatalf("GetAnalyzerInfo failed: %v", err)
	}

	if info.DisplayName != "My Policy Pack" {
		t.Errorf("expected info.DisplayName = %q, got %q", "My Policy Pack", info.DisplayName)
	}

	if len(info.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(info.Policies))
	}
	pol := info.Policies[0]
	if pol.DisplayName != "No Public Access" {
		t.Errorf("expected policy DisplayName = %q, got %q", "No Public Access", pol.DisplayName)
	}
	if pol.Description != "Denies resources with public ACLs." {
		t.Errorf("expected policy Description = %q, got %q", "Denies resources with public ACLs.", pol.Description)
	}
	if pol.Message != "Resource has public access" {
		t.Errorf("expected policy Message = %q, got %q", "Resource has public access", pol.Message)
	}
}

// TestLoadPolicyPack_ReadsPulumiPolicyYaml verifies that loadPolicyPack reads
// PulumiPolicy.yaml and populates InputFormat and Description on the pack.
func TestLoadPolicyPack_ReadsPulumiPolicyYaml(t *testing.T) {
	t.Parallel()

	t.Run("KubernetesAdmission", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		manifest := `description: K8s Gatekeeper Policies
runtime: opa
inputFormat: kubernetes-admission
`
		if err := os.WriteFile(filepath.Join(dir, "PulumiPolicy.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`
package test
violation[msg] { msg := "fail" }
`), 0o644); err != nil {
			t.Fatal(err)
		}

		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		if pack.InputFormat != "kubernetes-admission" {
			t.Errorf("expected InputFormat = kubernetes-admission, got %q", pack.InputFormat)
		}
		if pack.Description != "K8s Gatekeeper Policies" {
			t.Errorf("expected Description from manifest, got %q", pack.Description)
		}
	})

	t.Run("EmptyInputFormat", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		manifest := `description: Standard Policy Pack
runtime: opa
`
		if err := os.WriteFile(filepath.Join(dir, "PulumiPolicy.yaml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`
package test
deny[msg] { msg := "fail" }
`), 0o644); err != nil {
			t.Fatal(err)
		}

		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		if pack.InputFormat != "" {
			t.Errorf("expected empty InputFormat, got %q", pack.InputFormat)
		}
		if pack.Description != "Standard Policy Pack" {
			t.Errorf("expected Description from manifest, got %q", pack.Description)
		}
	})

	t.Run("NoManifest", func(t *testing.T) {
		t.Parallel()
		dir := writeRegoFile(t, "policy.rego", `
package test
deny[msg] { msg := "fail" }
`)
		pack, _, err := loadPolicyPack(dir)
		if err != nil {
			t.Fatalf("loadPolicyPack failed: %v", err)
		}
		if pack.InputFormat != "" {
			t.Errorf("expected empty InputFormat when no manifest, got %q", pack.InputFormat)
		}
		if pack.Description != "" {
			t.Errorf("expected empty Description when no manifest, got %q", pack.Description)
		}
	})
}

// TestLoadPolicyPack_InvalidInputFormat verifies that loadPolicyPack returns an
// error for unsupported inputFormat values.
func TestLoadPolicyPack_InvalidInputFormat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := `description: Bad Pack
runtime: opa
inputFormat: unsupported-format
`
	if err := os.WriteFile(filepath.Join(dir, "PulumiPolicy.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`
package test
deny[msg] { msg := "fail" }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadPolicyPack(dir)
	if err == nil {
		t.Fatal("expected error for unsupported inputFormat")
	}
	if !strings.Contains(err.Error(), "unsupported inputFormat") {
		t.Errorf("expected 'unsupported inputFormat' in error, got: %v", err)
	}
}

// TestLoadPolicyPack_MalformedManifest verifies that loadPolicyPack returns an
// error when PulumiPolicy.yaml contains invalid YAML.
func TestLoadPolicyPack_MalformedManifest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PulumiPolicy.yaml"), []byte(":::invalid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(`
package test
deny[msg] { msg := "fail" }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadPolicyPack(dir)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

// TestLoadPolicies_InvalidRego verifies that loadPolicyPack returns an error
// when Rego files contain syntax errors.
func TestLoadPolicies_InvalidRego(t *testing.T) {
	t.Parallel()
	dir := writeRegoFile(t, "policy.rego", `
package test

deny[msg] {
    this is not valid rego !!!
}
`)
	_, _, err := loadPolicyPack(dir)
	if err == nil {
		t.Fatal("expected loadPolicyPack to fail for invalid Rego syntax")
	}
	if !strings.Contains(err.Error(), "policy compilation failed") {
		t.Errorf("expected compilation error, got: %v", err)
	}
}

// TestLoadPolicies_PackageMismatch verifies that loadPolicyPack returns an error
// when Rego files use different package names.
func TestLoadPolicies_PackageMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file1 := `
package alpha

deny[msg] {
    msg := "alpha deny"
}
`
	file2 := `
package beta

warn[msg] {
    msg := "beta warn"
}
`
	if err := os.WriteFile(filepath.Join(dir, "alpha.rego"), []byte(file1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beta.rego"), []byte(file2), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadPolicyPack(dir)
	if err == nil {
		t.Fatal("expected loadPolicyPack to fail for package name mismatch")
	}
	if !strings.Contains(err.Error(), "unexpected package name") {
		t.Errorf("expected package mismatch error, got: %v", err)
	}
}

// TestLoadPolicies_EmptyDirectory verifies that loadPolicyPack handles a directory
// with no .rego files gracefully (empty pack, no error).
func TestLoadPolicies_EmptyDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	pack, _, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("expected no error for empty directory, got: %v", err)
	}
	if len(pack.Policies) != 0 {
		t.Errorf("expected 0 policies for empty directory, got %d", len(pack.Policies))
	}
}

// TestLoadPolicies_MultiModuleDedupe verifies that when multiple .rego files
// define the same rule name, only one policy entry is created (no duplicates)
// and a warning is emitted to stderr.
// This test captures os.Stderr so it must not run in parallel.
func TestLoadPolicies_MultiModuleDedupe(t *testing.T) {
	dir := t.TempDir()
	file1 := `
package test

deny[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`
	file2 := `
package test

deny[msg] {
    not input.encryption
    msg := "encryption required"
}
`
	if err := os.WriteFile(filepath.Join(dir, "acl.rego"), []byte(file1), 0o644); err != nil {
		t.Fatalf("failed to write acl.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "encryption.rego"), []byte(file2), 0o644); err != nil {
		t.Fatalf("failed to write encryption.rego: %v", err)
	}

	// Capture stderr to verify the duplicate warning is emitted.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	pack, _, loadErr := loadPolicyPack(dir)

	_ = w.Close()
	os.Stderr = origStderr

	stderrBytes, _ := io.ReadAll(r)
	stderrOutput := string(stderrBytes)

	if loadErr != nil {
		t.Fatalf("loadPolicyPack failed: %v", loadErr)
	}

	// Count how many policies have the name "deny".
	count := 0
	for _, p := range pack.Policies {
		if p.Name == "deny" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 'deny' policy entry, got %d", count)
	}

	// Verify that a warning was emitted for the duplicate rule.
	if !strings.Contains(stderrOutput, "warning: duplicate rule") {
		t.Errorf("expected duplicate rule warning on stderr, got: %q", stderrOutput)
	}
}

// loadPolicyPackCapturingStderr loads a policy pack from the given Rego source while
// capturing everything written to os.Stderr, returning the captured output. Because it
// swaps os.Stderr it must not run in parallel.
func loadPolicyPackCapturingStderr(t *testing.T, rego string) (*policyPack, string) {
	t.Helper()
	dir := writeRegoFile(t, "policy.rego", rego)

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	pack, _, loadErr := loadPolicyPack(dir)

	_ = w.Close()
	os.Stderr = origStderr

	stderrBytes, _ := io.ReadAll(r)
	if loadErr != nil {
		t.Fatalf("loadPolicyPack failed: %v", loadErr)
	}
	return pack, string(stderrBytes)
}

// TestLoadPolicies_WarnsOnUnrecognizedRule verifies that rules whose names look like
// they were intended to be evaluated rules — but use the wrong casing, a near-miss
// spelling, or a bad separator — produce a loud stderr warning and are not evaluated.
// These tests capture os.Stderr so they must not run in parallel.
func TestLoadPolicies_WarnsOnUnrecognizedRule(t *testing.T) {
	cases := []struct {
		name     string
		ruleName string
		rego     string
	}{
		{
			name:     "WrongCase",
			ruleName: "denyPublicBuckets",
			rego: `
package test

denyPublicBuckets[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`,
		},
		{
			name:     "Misspelling",
			ruleName: "denies_public",
			rego: `
package test

denies_public[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`,
		},
		{
			name:     "StackMisspelling",
			ruleName: "stack_denies_public",
			rego: `
package test

stack_denies_public[msg] {
    r := input.resources[_]
    r.acl == "public-read"
    msg := "public ACL not allowed"
}
`,
		},
		{
			name:     "StackWrongCase",
			ruleName: "stackDeny",
			rego: `
package test

stackDeny[msg] {
    count(input.resources) > 10
    msg := "too many resources"
}
`,
		},
		{
			name:     "WarningTypo",
			ruleName: "warning_no_tags",
			rego: `
package test

warning_no_tags[msg] {
    not input.tags
    msg := "missing tags"
}
`,
		},
		{
			// The owner's explicit example: an imperative policy verb with no
			// recognized prefix. Caught by both the broadened name heuristic and the
			// set-producing shape.
			name:     "ImperativeRequire",
			ruleName: "require_versioning",
			rego: `
package test

require_versioning[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.versioning.enabled
    msg := "versioning must be enabled"
}
`,
		},
		{
			name:     "ImperativeMust",
			ruleName: "must_have_tags",
			rego: `
package test

must_have_tags[msg] {
    not input.tags
    msg := "resources must have tags"
}
`,
		},
		{
			name:     "ImperativeEnsure",
			ruleName: "ensure_https",
			rego: `
package test

ensure_https[msg] {
    input.protocol != "https"
    msg := "https must be used"
}
`,
		},
		{
			name:     "ImperativeCheck",
			ruleName: "check_public",
			rego: `
package test

check_public[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pack, stderrOutput := loadPolicyPackCapturingStderr(t, tc.rego)

			// The rule must not have been loaded as an evaluated policy.
			if r := findRule(pack, tc.ruleName); r != nil {
				t.Errorf("expected rule %q to be skipped, but it was loaded", tc.ruleName)
			}

			// A warning naming the rule and explaining the fix must be emitted.
			if !strings.Contains(stderrOutput, "will NOT be evaluated") {
				t.Errorf("expected unrecognized-rule warning, got: %q", stderrOutput)
			}
			if !strings.Contains(stderrOutput, tc.ruleName) {
				t.Errorf("expected warning to name the rule %q, got: %q", tc.ruleName, stderrOutput)
			}
			if !strings.Contains(stderrOutput, "Rename it to start with") {
				t.Errorf("expected warning to explain the fix, got: %q", stderrOutput)
			}
		})
	}
}

// TestLoadPolicies_WarnsOnPolicyShapedRule verifies the primary, name-independent
// trigger: a partial set rule that builds up a collection of messages (the deny/warn
// shape) is flagged even when its name matches no keyword heuristic, because its shape
// is the strongest signal the author meant it to be a policy. This test captures
// os.Stderr so it must not run in parallel.
func TestLoadPolicies_WarnsOnPolicyShapedRule(t *testing.T) {
	rego := `
package test

s3_bucket_policy[msg] {
    input.acl == "public-read"
    msg := "public ACL not allowed"
}
`
	pack, stderrOutput := loadPolicyPackCapturingStderr(t, rego)

	if findRule(pack, "s3_bucket_policy") != nil {
		t.Error("expected policy-shaped but unprefixed rule to be skipped, but it was loaded")
	}
	if !strings.Contains(stderrOutput, "will NOT be evaluated") {
		t.Errorf("expected warning for policy-shaped rule, got: %q", stderrOutput)
	}
	if !strings.Contains(stderrOutput, "s3_bucket_policy") {
		t.Errorf("expected warning to name the rule, got: %q", stderrOutput)
	}
	if !strings.Contains(stderrOutput, "set of messages") {
		t.Errorf("expected warning to cite the set-producing shape, got: %q", stderrOutput)
	}
}

// TestLoadPolicies_NoWarnOnLegitimateHelpers verifies that genuine helper routines —
// boolean rules, value rules, and functions whose names do not look like a mistyped
// rule — are silently treated as library routines without triggering the
// unrecognized-rule warning. These are distinguished from policies by shape: a real
// policy is a partial set/object rule (Head.Key set, no args), whereas helpers are
// booleans, values, or functions. This test captures os.Stderr so it must not run in
// parallel.
func TestLoadPolicies_NoWarnOnLegitimateHelpers(t *testing.T) {
	rego := `
package test

is_public {
    input.acl == "public-read"
}

is_exempt {
    input.tags.exempt == "true"
}

has_encryption {
    input.serverSideEncryptionConfiguration
}

required_labels = ["env", "owner"]

valid_cidr(cidr) {
    cidr != "0.0.0.0/0"
}

deny_public[msg] {
    is_public
    not is_exempt
    msg := "public ACL not allowed"
}
`
	pack, stderrOutput := loadPolicyPackCapturingStderr(t, rego)

	// The real rule should still load with no warning.
	if findRule(pack, "deny_public") == nil {
		t.Error("expected deny_public rule to be loaded")
	}

	// None of the helpers should be loaded as evaluated rules; they remain usable as
	// library routines (deny_public above references is_public/is_exempt and compiles).
	for _, helper := range []string{"is_public", "is_exempt", "has_encryption", "required_labels", "valid_cidr"} {
		if findRule(pack, helper) != nil {
			t.Errorf("helper %q should not be loaded as a policy", helper)
		}
	}

	// No unrecognized-rule warning should have been emitted for any helper.
	if strings.Contains(stderrOutput, "will NOT be evaluated") {
		t.Errorf("did not expect unrecognized-rule warning for helpers, got: %q", stderrOutput)
	}
}
