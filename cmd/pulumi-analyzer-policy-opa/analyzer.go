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
	"os"

	"github.com/blang/semver"

	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

// VersionString is set via ldflags at build time using scripts/get-version.
var VersionString = "0.0.1+dev"

// analyzer implements the Analyzer interface needed to plug into Pulumi as a policy analyzer.
type analyzer struct {
	pack          *policyPack
	e             *evaler
	policyConfig  map[string]plugin.AnalyzerPolicyConfig // stored by Configure()
	configChecked bool                                    // guards one-time missing-config warning
}

func NewAnalyzer(
	pack *policyPack,
	e *evaler,
) plugin.Analyzer {
	return &analyzer{
		pack: pack,
		e:    e,
	}
}

func (a *analyzer) Name() tokens.QName {
	return tokens.QName(a.pack.Name)
}

func (a *analyzer) Analyze(r plugin.AnalyzerResource) (plugin.AnalyzeResponse, error) {
	a.warnMissingConfig()

	// Build the enriched input object containing both resource properties and metadata
	// (type, urn, name, options, provider) so that OPA policies can access the full context.
	// TODO: to attain rule compatibility with OPA rules written for, say, the Kubernetes Admission
	//     Controller, there is a very different schema we would need to follow. It's possible we should
	//     make the schema translation pluggable and customizable for certain policy packs and/or providers.
	obj := buildOPAInput(r)
	results, err := a.e.evalPolicyPack(context.Background(), a.pack, obj, resourceScope, a.policyConfig)
	if err != nil {
		return plugin.AnalyzeResponse{}, err
	}

	return plugin.AnalyzeResponse{Diagnostics: buildDiagnostics(results, r.URN, a.policyConfig)}, nil
}

func (a *analyzer) AnalyzeStack(resources []plugin.AnalyzerStackResource) (plugin.AnalyzeResponse, error) {
	a.warnMissingConfig()

	// Short-circuit if no stack-level rules exist.
	hasStackRules := false
	for _, pol := range a.pack.Policies {
		if pol.Scope == stackScope {
			hasStackRules = true
			break
		}
	}
	if !hasStackRules {
		return plugin.AnalyzeResponse{}, nil
	}

	// Build the stack-level input containing all resources.
	obj := buildStackOPAInput(resources)
	results, err := a.e.evalPolicyPack(context.Background(), a.pack, obj, stackScope, a.policyConfig)
	if err != nil {
		return plugin.AnalyzeResponse{}, err
	}

	// Use the stack URN for stack-level diagnostics, derived from the first resource.
	var stackURN resource.URN
	if len(resources) > 0 {
		urn := resources[0].URN
		stackURN = resource.DefaultRootStackURN(urn.Stack(), urn.Project())
	}
	return plugin.AnalyzeResponse{Diagnostics: buildDiagnostics(results, stackURN, a.policyConfig)}, nil
}

func (a *analyzer) Remediate(r plugin.AnalyzerResource) (plugin.RemediateResponse, error) {
	// OPA analyzer does not support remediation
	return plugin.RemediateResponse{}, nil
}

func (a *analyzer) GetAnalyzerInfo() (plugin.AnalyzerInfo, error) {
	var policies []plugin.AnalyzerPolicyInfo
	for _, pol := range a.pack.Policies {
		var policyType plugin.AnalyzerPolicyType
		if pol.Scope == stackScope {
			policyType = plugin.AnalyzerPolicyTypeStack
		} else {
			policyType = plugin.AnalyzerPolicyTypeResource
		}

		policies = append(policies, plugin.AnalyzerPolicyInfo{
			Name:             pol.Name,
			DisplayName:      pol.DisplayName,
			Description:      pol.Description,
			Message:          pol.Message,
			EnforcementLevel: enforcementLevelToAPI(pol.Level),
			Type:             policyType,
			ConfigSchema:     pol.ConfigSchema,
		})
	}
	return plugin.AnalyzerInfo{
		Name:           a.pack.Name,
		DisplayName:    a.pack.DisplayName,
		Policies:       policies,
		SupportsConfig: true,
	}, nil
}

func (a *analyzer) GetPluginInfo() (workspace.PluginInfo, error) {
	version, err := semver.Parse(VersionString)
	if err != nil {
		return workspace.PluginInfo{}, err
	}
	return workspace.PluginInfo{
		Version: &version,
	}, nil
}

func (a *analyzer) Configure(policyConfig map[string]plugin.AnalyzerPolicyConfig) error {
	// Validate enforcement levels before storing.
	for name, cfg := range policyConfig {
		if cfg.EnforcementLevel != "" {
			switch cfg.EnforcementLevel {
			case apitype.Advisory, apitype.Mandatory, apitype.Disabled:
				// valid
			default:
				return fmt.Errorf("invalid enforcement level %q for policy %q", cfg.EnforcementLevel, name)
			}
		}
	}
	a.policyConfig = policyConfig
	return nil
}

// warnMissingConfig logs a one-time warning for each policy that declares a config
// schema but was not given any configuration properties. Without config, rules that
// reference data.config will silently not fire.
func (a *analyzer) warnMissingConfig() {
	if a.configChecked {
		return
	}
	a.configChecked = true

	for _, pol := range a.pack.Policies {
		if pol.ConfigSchema == nil {
			continue
		}
		if a.policyConfig != nil {
			if cfg, ok := a.policyConfig[pol.Name]; ok && len(cfg.Properties) > 0 {
				continue
			}
		}
		fmt.Fprintf(os.Stderr, "warning: policy %q declares a config schema but no configuration was provided; "+
			"rules referencing data.config will not fire\n", pol.Name)
	}
}

func (a *analyzer) Cancel(ctx context.Context) error {
	// No cancellation needed
	return nil
}

func (a *analyzer) Close() error {
	// No resources to close
	return nil
}

// buildDiagnostics translates OPA evaluation results into Pulumi analyzer diagnostics.
// For resource-level rules, urn is the individual resource's URN. For stack-level rules,
// urn is the root stack URN since violations span multiple resources.
//
// If policyConfig contains an enforcement level override for a rule, it takes precedence
// over the rule-prefix-derived level. Disabled rules are omitted from the output.
func buildDiagnostics(
	results []evalPolicyResult,
	urn resource.URN,
	policyConfig map[string]plugin.AnalyzerPolicyConfig,
) []plugin.AnalyzeDiagnostic {
	var diagnostics []plugin.AnalyzeDiagnostic
	for _, result := range results {
		level := enforcementLevelToAPI(result.level)

		// Apply enforcement level override from configuration if present.
		// Checks policy-specific config first, then the "all" pack-wide default.
		if override := configuredEnforcementLevel(policyConfig, result.rule); override != "" {
			level = override
		}

		// Skip diagnostics for disabled rules.
		if level == apitype.Disabled {
			continue
		}

		diagnostics = append(diagnostics, plugin.AnalyzeDiagnostic{
			PolicyName:        result.rule,
			PolicyPackName:    result.pack,
			PolicyPackVersion: VersionString,
			Message:           result.msg,
			URN:               urn,
			EnforcementLevel:  level,
		})
	}
	return diagnostics
}

// enforcementLevelToAPI converts an internal enforcementLevel to the Pulumi API type.
func enforcementLevelToAPI(level enforcementLevel) apitype.EnforcementLevel {
	switch level {
	case advisoryRule:
		return apitype.Advisory
	case disabledRule:
		return apitype.Disabled
	default:
		return apitype.Mandatory
	}
}

// buildOPAInput constructs the input object passed to OPA policy evaluation.
// It starts with the resource metadata fields (type, urn, __name, options, provider,
// properties) and then overlays the resource's own properties on top so that Rego
// policies can access the full AnalyzerResource context.
//
// If a resource property has the same key as a metadata field, the resource property
// takes precedence for backwards compatibility. Policy authors can use the __-prefixed
// versions (__type, __urn, __name, __options, __provider, __properties) to reliably
// access metadata regardless of property name collisions.
func buildOPAInput(r plugin.AnalyzerResource) map[string]any {
	obj := make(map[string]any)

	// Set metadata fields first so resource properties can override them.
	obj["type"] = string(r.Type)
	obj["urn"] = string(r.URN)
	obj["name"] = r.Name
	obj["__name"] = r.Name

	// Add resource options.
	opts := map[string]any{
		"protect":                 r.Options.Protect,
		"ignoreChanges":           r.Options.IgnoreChanges,
		"deleteBeforeReplace":     r.Options.DeleteBeforeReplace,
		"additionalSecretOutputs": propertyKeysToStrings(r.Options.AdditionalSecretOutputs),
		"aliasURNs":               aliasURNsToStrings(r.Options.AliasURNs),
		"aliases":                 aliasesToMaps(r.Options.Aliases),
		"customTimeouts": map[string]any{
			"create": r.Options.CustomTimeouts.Create,
			"update": r.Options.CustomTimeouts.Update,
			"delete": r.Options.CustomTimeouts.Delete,
		},
		"parent": string(r.Options.Parent),
	}
	obj["options"] = opts

	// Add provider info. Use an empty map when provider is nil so that
	// input.provider and input.__provider are always defined.
	var providerInfo map[string]any
	if r.Provider != nil {
		providerInfo = map[string]any{
			"type":       string(r.Provider.Type),
			"name":       r.Provider.Name,
			"urn":        string(r.Provider.URN),
			"properties": r.Provider.Properties.Mappable(),
		}
	} else {
		providerInfo = map[string]any{}
	}
	obj["provider"] = providerInfo

	// Expose the properties as a nested "properties" bag so that policies
	// can access them via input.properties.<key> without metadata key collisions.
	obj["properties"] = r.Properties.Mappable()

	// Overlay resource properties so they take precedence over metadata
	// fields at the top level for backwards compatibility.
	for k, v := range r.Properties.Mappable() {
		obj[k] = v
	}

	// Set __-prefixed metadata fields last so they are always available as a
	// collision-safe escape hatch, even if a resource property has the same name
	// as a metadata field (e.g. input.__type always returns the resource type).
	obj["__type"] = string(r.Type)
	obj["__urn"] = string(r.URN)
	// __name is already prefixed and set above; re-set it here to guarantee it
	// survives a (highly unlikely) resource property named "__name".
	obj["__name"] = r.Name
	obj["__options"] = opts
	obj["__properties"] = r.Properties.Mappable()
	obj["__provider"] = providerInfo

	return obj
}

// buildStackOPAInput constructs the input object passed to OPA stack policy evaluation.
// It creates a map with a "resources" key containing an array of enriched resource objects,
// each including the resource's properties, metadata, dependencies, and property dependencies.
func buildStackOPAInput(resources []plugin.AnalyzerStackResource) map[string]any {
	resourceList := make([]map[string]any, 0)

	for _, sr := range resources {
		obj := buildOPAInput(sr.AnalyzerResource)

		// Override options.parent with the AnalyzerStackResource.Parent if non-empty,
		// as it may provide a more accurate value than Options.Parent.
		if sr.Parent != "" {
			if opts, ok := obj["options"].(map[string]any); ok {
				opts["parent"] = string(sr.Parent)
			}
		}

		// Add stack-level fields.
		if sr.Dependencies != nil {
			deps := make([]string, len(sr.Dependencies))
			for i, d := range sr.Dependencies {
				deps[i] = string(d)
			}
			obj["dependencies"] = deps
		}

		if sr.PropertyDependencies != nil {
			propDeps := make(map[string][]string)
			for k, urns := range sr.PropertyDependencies {
				strs := make([]string, len(urns))
				for i, u := range urns {
					strs[i] = string(u)
				}
				propDeps[string(k)] = strs
			}
			obj["propertyDependencies"] = propDeps
		}

		resourceList = append(resourceList, obj)
	}

	return map[string]any{
		"resources": resourceList,
	}
}

// propertyKeysToStrings converts a slice of PropertyKey to a slice of strings.
func propertyKeysToStrings(keys []resource.PropertyKey) []string {
	if keys == nil {
		return nil
	}
	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = string(k)
	}
	return result
}

// aliasURNsToStrings converts a slice of URN to a slice of strings.
func aliasURNsToStrings(urns []resource.URN) []string {
	if urns == nil {
		return nil
	}
	result := make([]string, len(urns))
	for i, u := range urns {
		result[i] = string(u)
	}
	return result
}

// aliasesToMaps converts a slice of Alias to a slice of maps for OPA consumption.
func aliasesToMaps(aliases []resource.Alias) []map[string]any {
	if aliases == nil {
		return nil
	}
	result := make([]map[string]any, len(aliases))
	for i, a := range aliases {
		result[i] = map[string]any{
			"urn":      string(a.URN),
			"name":     a.Name,
			"type":     a.Type,
			"project":  a.Project,
			"stack":    a.Stack,
			"parent":   string(a.Parent),
			"noParent": a.NoParent,
		}
	}
	return result
}
