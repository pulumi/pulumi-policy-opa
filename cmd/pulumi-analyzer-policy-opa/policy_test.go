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

// TestLoadPolicies_StackDenyRule verifies that a stack_deny rule is classified
// as mandatory with stack scope.
func TestLoadPolicies_StackDenyRule(t *testing.T) {
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
}

// TestLoadPolicies_StackWarnRule verifies that a stack_warn rule is classified
// as advisory with stack scope.
func TestLoadPolicies_StackWarnRule(t *testing.T) {
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
}

// TestLoadPolicies_StackDenySuffixRule verifies that a stack_deny rule with a
// suffix (e.g., stack_deny_no_public_buckets) is classified as mandatory with stack scope.
func TestLoadPolicies_StackDenySuffixRule(t *testing.T) {
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
}

// TestLoadPolicies_MixedRules verifies that a rego file with both resource-level
// and stack-level rules classifies each correctly.
func TestLoadPolicies_MixedRules(t *testing.T) {
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
}

// TestLoadPolicies_StackViolationRule verifies that a stack_violation rule is
// classified as mandatory with stack scope (symmetric with deny/violation).
func TestLoadPolicies_StackViolationRule(t *testing.T) {
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
}

// TestLoadPolicies_RuleNameWithDigits verifies that rule names containing digits
// in their suffixes are correctly recognized by the regex patterns.
func TestLoadPolicies_RuleNameWithDigits(t *testing.T) {
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

// TestLoadPolicies_MultiModuleDedupe verifies that when multiple .rego files
// define the same rule name, only one policy entry is created (no duplicates)
// and a warning is emitted to stderr.
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
