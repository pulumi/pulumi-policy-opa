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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"gopkg.in/yaml.v3"
)

// InputFormatKubernetesAdmission is the inputFormat value that enables
// Gatekeeper-compatible AdmissionReview wrapping for Kubernetes resources.
const InputFormatKubernetesAdmission = "kubernetes-admission"

// policyPackManifest represents the contents of PulumiPolicy.yaml.
type policyPackManifest struct {
	Description string `yaml:"description"`
	Runtime     string `yaml:"runtime"`
	InputFormat string `yaml:"inputFormat"`
}

// Rego modules contain rules, some of which have prefixes. Only those with the appropriate
// prefix will be considered rules for evaluation -- all others are used as library routines.
// Resource-level rules are evaluated per-resource via Analyze().
// Stack-level rules (stack_ prefix) are evaluated once for the entire stack via AnalyzeStack().
var (
	denyRulePrefix      = regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
	warnRulePrefix      = regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
	stackDenyRulePrefix = regexp.MustCompile("^stack_(deny|violation)(_[a-zA-Z0-9]+)*$")
	stackWarnRulePrefix = regexp.MustCompile("^stack_warn(_[a-zA-Z0-9]+)*$")
)

// ruleLikeNamePrefix matches rule names that look like they were intended to be
// evaluated rules but use the wrong casing or separator or a plural/conjugated form
// (e.g. "Deny", "denyPublic", "deny-public", "denies"), or an imperative policy verb
// that implies intent to enforce something (e.g. "require_versioning", "must_have_tags",
// "ensure_https", "check_public").
//
// This is exact-keyword matching at a word boundary, not fuzzy spelling correction: an
// arbitrary typo like "deniy" or "violaton" is NOT matched here. Such a rule can still
// be flagged by the other warnUnrecognizedRule trigger if it has the set-producing shape
// of a policy.
//
// Each keyword must be a discrete leading token — it has to be followed by a word
// boundary (underscore, separator, end-of-name, or a camelCase capital/digit), not
// just more lowercase letters. That keeps the imperative verbs from swallowing
// legitimate value/boolean helpers whose names merely begin with the same letters
// (e.g. "required_labels", "checksum", "blocklist", "validated_at"), which along with
// helpers like "is_public"/"valid_cidr"/"has_encryption" never trip the name
// heuristic. A match here that is NOT also matched by one of the exact prefix regexes
// above is one of two triggers (the other being the rule's set-producing shape) that
// warnUnrecognizedRule reports.
//
// The keyword groups are scoped case-insensitive (?i:...), but the trailing
// word-boundary class [A-Z0-9] is intentionally case-sensitive: a global (?i) flag
// would make [A-Z] match any letter and defeat the boundary, re-admitting
// "required_labels", "checksum", etc.
var ruleLikeNamePrefix = regexp.MustCompile(
	`^(?i:stack[_-]?)?(?i:` +
		`deny|denies|violation|violations|violate|warn|warns|warning|warnings|` +
		`require|requires|must|ensure|ensures|enforce|enforces|should|` +
		`check|checks|validate|validates|verify|verifies|disallow|disallows|` +
		`prohibit|prohibits|forbid|forbids|restrict|restricts|block|blocks|` +
		`prevent|prevents|mandate|mandates|reject|rejects` +
		`)(_|-|[A-Z0-9]|$)`)

// Authoring-time diagnostic codes. Each warning is emitted as "warning[<code>]: ..." so
// tooling and LLM agents can recognize and gate on a diagnostic class by its stable code
// without depending on the exact prose, which may change between releases.
const (
	diagUnrecognizedRule = "opa/unrecognized-rule"
	diagZeroRules        = "opa/zero-rules"
	diagDuplicateRule    = "opa/duplicate-rule"
	diagMissingConfig    = "opa/missing-config"
)

// warnf writes a single authoring-time warning to stderr, tagged with a stable diagnostic
// code: "warning[<code>]: <message>".
func warnf(code, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning[%s]: %s\n", code, fmt.Sprintf(format, args...))
}

// loadPolicyPack loads the metadata about a pack and its policies from a directory containing OPA *.rego files.
func loadPolicyPack(dir string) (*policyPack, *evaler, error) {
	// Read the optional PulumiPolicy.yaml manifest for pack metadata.
	var manifest policyPackManifest
	manifestPath := filepath.Join(dir, "PulumiPolicy.yaml")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			return nil, nil, errors.Wrapf(err, "parsing %s", manifestPath)
		}
		if manifest.InputFormat != "" && manifest.InputFormat != InputFormatKubernetesAdmission {
			return nil, nil, errors.Errorf(
				"unsupported inputFormat %q in %s (valid values: %q)",
				manifest.InputFormat, manifestPath, InputFormatKubernetesAdmission)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, errors.Wrapf(err, "reading %s", manifestPath)
	}

	// Next gather up all the OPA rego files to run and prepare to compile them.
	modules := make(map[string]string)
	if err := filepath.Walk(dir, func(
		path string,
		info os.FileInfo,
		fileErr error,
	) error {
		if fileErr != nil {
			return errors.Wrapf(fileErr, "searching for policies in %s", dir)
		} else if !info.IsDir() && filepath.Ext(path) == ".rego" {
			// Read the program into memory so we can compile it below.
			b, err := os.ReadFile(path)
			if err != nil {
				return errors.Wrapf(err, "reading policy %s", path)
			}

			// Take the relative path from the target rules dir, remove the prefix, and use that as the rule name.
			name, err := filepath.Rel(dir, path)
			if err != nil {
				return errors.Wrapf(err, "normalizing path (%s, %s)", dir, path)
			}
			dotIndex := strings.LastIndex(name, ".")
			modules[name[:dotIndex]] = string(b)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	// Compile all of the policy files so we can error out early if there are problems.
	// ProcessAnnotation enables extraction of METADATA annotations (title, description, etc.)
	// from Rego rules and modules so we can populate policy metadata fields.
	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		ParserOptions: ast.ParserOptions{
			RegoVersion:       ast.RegoV0,
			ProcessAnnotation: true,
		},
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "policy compilation failed")
	}

	// Build up a list of rules.
	var packName string
	var policies []*policyRule
	totalRules := 0
	existing := make(map[string]struct{})
	warnedUnrecognized := make(map[string]struct{})
	for name, module := range compiler.Modules {
		// First determine the package name. This should match for all rules.
		pkg := module.Package.String()
		if strings.Index(pkg, "package ") != 0 {
			return nil, nil, errors.Errorf("malformed package name, expected 'package' prefix: %s", pkg)
		}
		pkg = pkg[len("package "):]
		if packName == "" {
			packName = pkg
		} else if packName != pkg {
			return nil, nil, errors.Errorf("unexpected package name differences: got %s, expected %s", pkg, packName)
		}

		// Next go through all rules and tease them apart, skipping duplicates.
		for _, rule := range module.Rules {
			totalRules++
			ruleName := rule.Head.Name.String()

			// Only process those that are legitimate errors or warnings. Other "rules" are
			// actually just libraries that can be used as routines in authoring other rules.
			// Check stack-level prefixes before resource-level prefixes since
			// stack_deny/stack_warn are distinct from deny/warn.
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
				// This rule does not match any recognized prefix, so it will be
				// treated as a library routine and never evaluated. If the rule has
				// the shape of a policy (a partial set/object rule — Head.Key set, no
				// function args) or its name looks like it was *meant* to be a rule
				// (wrong casing, a typo, or an imperative policy verb), warn loudly so
				// the author gets a signal instead of a rule that silently never fires.
				policyShaped := rule.Head.Key != nil && len(rule.Head.Args) == 0
				isFunction := len(rule.Head.Args) > 0
				if _, warned := warnedUnrecognized[ruleName]; !warned {
					if warnUnrecognizedRule(ruleName, name, policyShaped, isFunction) {
						warnedUnrecognized[ruleName] = struct{}{}
					}
				}
				continue // skip
			}

			if _, has := existing[ruleName]; has {
				warnf(diagDuplicateRule, "rule %q in module %q has the same name as an earlier rule; OPA still "+
					"merges and evaluates every body with this name, so no logic is dropped — only the duplicate "+
					"policy-metadata entry is skipped. Give the rules distinct names if you meant them to be "+
					"separate policies.", ruleName, name)
				continue
			}
			existing[ruleName] = struct{}{}

			// Extract metadata from OPA rule annotations (# METADATA blocks).
			var description, message, displayName string
			displayName = name
			if len(rule.Annotations) > 0 {
				ann := rule.Annotations[0]
				if ann.Title != "" {
					displayName = ann.Title
				}
				if ann.Description != "" {
					description = ann.Description
				}
				if msg, ok := ann.Custom["message"].(string); ok {
					message = msg
				}
			}

			policies = append(policies, &policyRule{
				Name:        ruleName,
				DisplayName: displayName,
				Description: description,
				Message:     message,
				Level:       level,
				Scope:       scope,
			})
		}
	}

	// A pack that evaluates no rules silently enforces nothing — almost always an
	// authoring bug. Warn loudly, but don't fail to load (see warnZeroRules).
	if len(policies) == 0 {
		warnZeroRules(packName, totalRules)
	}

	// Load optional config schemas from config-schema.json alongside the Rego files.
	configSchemas := loadConfigSchemas(dir)
	for _, pol := range policies {
		if schema, ok := configSchemas[pol.Name]; ok {
			pol.ConfigSchema = schema
		}
	}

	// Derive pack DisplayName from module-level annotations if available.
	var packDisplayName string
	for _, module := range compiler.Modules {
		if len(module.Annotations) > 0 {
			for _, ann := range module.Annotations {
				if ann.Scope == "package" && ann.Title != "" {
					packDisplayName = ann.Title
					break
				}
			}
		}
		if packDisplayName != "" {
			break
		}
	}

	// Create the resulting policy pack metadata.
	pack := &policyPack{
		Name:        packName,
		DisplayName: packDisplayName,
		Description: manifest.Description,
		InputFormat: manifest.InputFormat,
		Policies:    policies,
	}

	// Make an evaluator that can actually apply the rules using the above compiler.
	e := &evaler{c: compiler}

	return pack, e, nil
}

// warnZeroRules emits a loud, stable-coded banner when a policy pack would evaluate no
// rules at all — either because every rule is a helper that matches no recognized prefix,
// or because the pack is empty. Such a pack silently enforces nothing, so the warning is
// formatted to be unmissable. It is a warning rather than a hard error so incremental
// authoring (a pack briefly with no rules) is not blocked; a CI or publish gate can key off
// the warning[opa/zero-rules] code to fail the build if it wants stricter behavior.
func warnZeroRules(packName string, totalRules int) {
	name := "this policy pack"
	if packName != "" {
		name = fmt.Sprintf("policy pack %q", packName)
	}

	var detail string
	if totalRules == 0 {
		detail = "it contains no policy rules at all"
	} else {
		detail = fmt.Sprintf("it defines %d rule(s) but none match a recognized prefix, so every "+
			"rule is treated as a helper and no policy will ever run", totalRules)
	}

	const bar = "========================================================================"
	fmt.Fprintf(os.Stderr, "%s\nwarning[%s]: %s will enforce NOTHING — %s. "+
		"Fix: name at least one rule deny/violation/warn (resource) or "+
		"stack_deny/stack_violation/stack_warn (stack), e.g. \"deny_public_buckets\". "+
		"Prefixes are case-sensitive and use underscores.\n%s\n",
		bar, diagZeroRules, name, detail, bar)
}

// warnUnrecognizedRule reports a rule that does not match a recognized prefix — so it is
// silently treated as a helper and never runs — but looks like it was meant to be
// evaluated. It returns true if it emitted a warning; the caller dedupes by rule name so
// each name is reported at most once, even when defined across multiple bodies. There are
// two independent triggers:
//
//   - policyShaped: the rule is a partial set/object rule (a key, no args) — the same
//     shape as a deny/warn rule — which is the most robust signal that the author
//     intended it as a policy regardless of what they named it; or
//   - its name matches ruleLikeNamePrefix — wrong casing, a near-miss spelling, or an
//     imperative policy verb (require/must/ensure/check/...) that implies enforcement.
//
// A function (a rule with arguments) is never reported by the name trigger, since a
// deny/warn policy never takes arguments — so a helper like "check(x)" stays quiet.
//
// Rules that are neither policy-shaped nor rule-like by name (genuine boolean/value/
// function helpers such as "is_public", "required_labels", "valid_cidr") are not
// reported.
func warnUnrecognizedRule(ruleName, module string, policyShaped, isFunction bool) bool {
	nameLooksRuleLike := !isFunction && ruleLikeNamePrefix.MatchString(ruleName)
	if !policyShaped && !nameLooksRuleLike {
		return false
	}

	var reason string
	switch {
	case policyShaped && nameLooksRuleLike:
		reason = "it has the partial set/object shape of a deny/warn rule and its name implies intent to enforce a policy"
	case policyShaped:
		reason = "it has the partial set/object shape of a deny/warn rule"
	default:
		reason = "its name implies intent to enforce a policy"
	}

	warnf(diagUnrecognizedRule, "rule %q in module %q will NOT be evaluated because its name does not "+
		"match a recognized rule prefix, so it is being treated as a helper routine. It was flagged because "+
		"%s. Fix: rename it to start with one of deny, violation, warn (resource-level) or stack_deny, "+
		"stack_violation, stack_warn (stack-level) — e.g. \"deny_public_buckets\", not \"denyPublicBuckets\" "+
		"or \"require_versioning\". Prefixes are case-sensitive and use underscores. Advisory: if this really "+
		"is a helper routine and not a policy, ignore this warning or rename it so it no longer looks "+
		"rule-like.",
		ruleName, module, reason)
	return true
}

// policyPack holds the metadata for a complete Pulumi policy package.
type policyPack struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"displayName"`
	Description string        `json:"description"`
	InputFormat string        `json:"inputFormat,omitempty"`
	Policies    []*policyRule `json:"policies"`
}

// policyRule holds the metadata for a Pulumi policy rule, in addition to the OPA rule authored in *.rego.
type policyRule struct {
	Name         string                             `json:"name"`
	DisplayName  string                             `json:"displayName"`
	Description  string                             `json:"description"`
	Message      string                             `json:"message"`
	Level        enforcementLevel                   `json:"enforcementLevel"`
	Scope        policyScope                        `json:"scope"`
	ConfigSchema *plugin.AnalyzerPolicyConfigSchema `json:"configSchema,omitempty"`
}

type enforcementLevel int

const (
	advisoryRule  enforcementLevel = 0
	mandatoryRule enforcementLevel = 1
	disabledRule  enforcementLevel = 2
)

type policyScope int

const (
	resourceScope policyScope = 0
	stackScope    policyScope = 1
)

// configSchemaFile represents the JSON structure of config-schema.json.
// It maps policy rule names to their config schema definitions.
//
// Example config-schema.json:
//
//	{
//	  "deny_large_instances": {
//	    "properties": {
//	      "maxInstanceSize": {
//	        "type": "string",
//	        "default": "t3.large"
//	      }
//	    },
//	    "required": ["maxInstanceSize"]
//	  }
//	}
type configSchemaFile map[string]struct {
	Properties map[string]plugin.JSONSchema `json:"properties"`
	Required   []string                     `json:"required,omitempty"`
}

// loadConfigSchemas loads optional config schema definitions from a
// config-schema.json file in the policy pack directory. Returns an empty
// map if the file does not exist or cannot be parsed.
func loadConfigSchemas(dir string) map[string]*plugin.AnalyzerPolicyConfigSchema {
	schemas := make(map[string]*plugin.AnalyzerPolicyConfigSchema)

	data, err := os.ReadFile(filepath.Join(dir, "config-schema.json"))
	if err != nil {
		return schemas // file is optional
	}

	var raw configSchemaFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return schemas // silently ignore malformed schema
	}

	for name, def := range raw {
		schemas[name] = &plugin.AnalyzerPolicyConfigSchema{
			Properties: def.Properties,
			Required:   def.Required,
		}
	}
	return schemas
}
