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
	existing := make(map[string]struct{})
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
				continue // skip
			}

			if _, has := existing[ruleName]; has {
				fmt.Fprintf(os.Stderr, "warning: duplicate rule %q in module %q, skipping\n", ruleName, name)
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
