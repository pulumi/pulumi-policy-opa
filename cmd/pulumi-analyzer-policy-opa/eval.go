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
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/pkg/errors"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
)

type evaler struct {
	c *ast.Compiler
}

func (e *evaler) evalPolicyPack(
	ctx context.Context,
	pack *policyPack,
	input any,
	scope policyScope,
	policyConfig map[string]plugin.AnalyzerPolicyConfig,
) ([]evalPolicyResult, error) {
	var results []evalPolicyResult

	// Build OPA data store with config properties so Rego rules can access
	// them via data.config.<policy_name>.<key>.
	store := buildConfigStore(policyConfig)

	for _, rule := range pack.Policies {
		if rule.Scope != scope {
			continue // skip rules not matching requested scope
		}

		// Skip rules that have been disabled via configuration.
		if configuredEnforcementLevel(policyConfig, rule.Name) == apitype.Disabled {
			continue
		}

		// When kubernetes-admission format is active, inject input.parameters
		// from the per-rule policy config so Gatekeeper rules can access them.
		evalInput := input
		if pack.InputFormat == InputFormatKubernetesAdmission {
			if policyConfig != nil {
				if cfg, ok := policyConfig[rule.Name]; ok && len(cfg.Properties) > 0 {
					evalInput = cloneInputWithParameters(input, cfg.Properties)
				}
			}
		}

		// Build a rego object that can be evaluated.
		opts := []func(*rego.Rego){
			rego.Query(fmt.Sprintf("data.%s.%s", pack.Name, rule.Name)),
			rego.Compiler(e.c),
			rego.Input(evalInput),
			rego.SetRegoVersion(ast.RegoV0),
		}
		if store != nil {
			opts = append(opts, rego.Store(store))
		}
		robj := rego.New(opts...)

		resultSet, err := robj.Eval(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "evaluating rule %s.%s", pack.Name, rule.Name)
		}

		for _, result := range resultSet {
			for _, expr := range result.Expressions {
				if ae, ok := expr.Value.([]any); ok && len(ae) > 0 {
					for _, v := range ae {
						msg := extractViolationMessage(v)
						results = append(results, evalPolicyResult{
							pack:  pack.Name,
							rule:  rule.Name,
							msg:   msg,
							level: rule.Level,
						})
					}
				}
			}
		}
	}

	return results, nil
}

// buildConfigStore creates an in-memory OPA store containing policy configuration
// properties under data.config.<policy_name>. Returns nil if no config properties
// are present.
func buildConfigStore(policyConfig map[string]plugin.AnalyzerPolicyConfig) storage.Store {
	if len(policyConfig) == 0 {
		return nil
	}

	configData := make(map[string]any)
	hasProperties := false
	for name, cfg := range policyConfig {
		if len(cfg.Properties) > 0 {
			configData[name] = cfg.Properties
			hasProperties = true
		}
	}
	if !hasProperties {
		return nil
	}

	return inmem.NewFromObject(map[string]any{
		"config": configData,
	})
}

type evalPolicyResult struct {
	pack  string
	rule  string
	msg   string
	level enforcementLevel
}

// extractViolationMessage extracts a human-readable message from an OPA rule result value.
// Gatekeeper rules return violation[{"msg": msg, ...}] (map values), while standard
// rules return deny["message string"]. This handles both formats.
func extractViolationMessage(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case map[string]any:
		if msg, ok := val["msg"].(string); ok {
			return msg
		}
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// cloneInputWithParameters creates a shallow copy of the input map and injects
// a "parameters" key containing the given properties. This lets Gatekeeper-style
// rules access per-rule config via input.parameters.
func cloneInputWithParameters(input any, parameters map[string]any) any {
	m, ok := input.(map[string]any)
	if !ok {
		return input
	}
	clone := make(map[string]any, len(m)+1)
	for k, v := range m {
		clone[k] = v
	}
	clone["parameters"] = parameters
	return clone
}

// configuredEnforcementLevel returns the enforcement level override for a policy
// from configuration. It checks the policy-specific config first, then falls back
// to the "all" key which applies a pack-wide default. Returns "" if no override
// is configured.
func configuredEnforcementLevel(
	policyConfig map[string]plugin.AnalyzerPolicyConfig,
	policyName string,
) apitype.EnforcementLevel {
	if policyConfig == nil {
		return ""
	}
	// Policy-specific override takes precedence.
	if cfg, ok := policyConfig[policyName]; ok && cfg.EnforcementLevel != "" {
		return cfg.EnforcementLevel
	}
	// Fall back to pack-wide "all" override.
	if cfg, ok := policyConfig["all"]; ok && cfg.EnforcementLevel != "" {
		return cfg.EnforcementLevel
	}
	return ""
}
