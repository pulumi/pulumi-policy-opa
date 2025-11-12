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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/pkg/errors"
)

// Rego modules contain rules, some of which have prefixes. Only those with the appropriate
// prefix will be considered rules for evaluation -- all others are used as library routines.
var (
	denyRulePrefix = regexp.MustCompile("^(deny|violation)(_[a-zA-Z]+)*$")
	warnRulePrefix = regexp.MustCompile("^warn(_[a-zA-Z]+)*$")
)

// loadPolicyPack loads the metadata about a pack and its policies from a directory containing OPA *.rego files.
func loadPolicyPack(dir string) (*policyPack, *evaler, error) {
	// First open the manifest file to learn more about the pack.
	// TODO: we need to do this in order to provide metadata about the package itself, like its name,
	// description, and so on. The idea here is to just put a PulumiPolicy.yaml inside the rules/ directory.

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
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "policy compilation failed")
	}

	// Buld up a list of rules.
	var packName string
	var policies []*policyRule
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
		existing := make(map[string]bool)
		for _, rule := range module.Rules {
			ruleName := rule.Head.Name.String()

			// Only process those that are legitimate errors or warnings. Other "rules" are
			// actually just libraries that can be used as routines in authoring other rules.
			var level enforcementLevel
			if denyRulePrefix.MatchString(ruleName) {
				level = mandatoryRule
			} else if warnRulePrefix.MatchString(ruleName) {
				level = advisoryRule
			} else {
				continue // skip
			}

			if _, has := existing[ruleName]; !has {
				existing[ruleName] = true
				policies = append(policies, &policyRule{
					Name:        ruleName,
					DisplayName: name,
					// TODO: Description, Message
					Level: level,
				})
			}
		}
	}

	// Create the resulting policy pack metadata.
	pack := &policyPack{
		Name: packName,
		// TODO: DisplayName
		Policies: policies,
	}

	// Make an evaluator that can actually apply the rules using the above compiler.
	e := &evaler{c: compiler}

	return pack, e, nil
}

// policyPack holds the metadata for a complete Pulumi policy package.
type policyPack struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"displayName"`
	Policies    []*policyRule `json:"policies"`
}

// policyRule holds the metadata for a Pulumi policy rule, in addition to the OPA rule authored in *.rego.
type policyRule struct {
	Name        string           `json:"name"`
	DisplayName string           `json:"displayName"`
	Description string           `json:"description"`
	Message     string           `json:"message"`
	Level       enforcementLevel `json:"enforcementLevel"`
}

type enforcementLevel int

const (
	advisoryRule  enforcementLevel = 0
	mandatoryRule enforcementLevel = 1
)
