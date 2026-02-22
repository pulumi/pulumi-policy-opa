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
	pack *policyPack
	e    *evaler
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
	var diagnostics []plugin.AnalyzeDiagnostic

	// Build the enriched input object containing both resource properties and metadata
	// (type, urn, name, options, provider) so that OPA policies can access the full context.
	// TODO: to attain rule compatibility with OPA rules written for, say, the Kubernetes Admission
	//     Controller, there is a very different schema we would need to follow. It's possible we should
	//     make the schema translation pluggable and customizable for certain policy packs and/or providers.
	obj := buildOPAInput(r)
	results, err := a.e.evalPolicyPack(context.Background(), a.pack, obj)
	if err != nil {
		return plugin.AnalyzeResponse{}, err
	}

	// Translate the policy results into the appropriate analyzer data structures.
	for _, result := range results {
		var level apitype.EnforcementLevel
		if result.level == advisoryRule {
			level = apitype.Advisory
		} else {
			level = apitype.Mandatory
		}
		diagnostics = append(diagnostics, plugin.AnalyzeDiagnostic{
			PolicyName:        result.rule,
			PolicyPackName:    result.pack,
			PolicyPackVersion: VersionString,
			Message:           result.msg,
			URN:               r.URN,
			EnforcementLevel:  level,
		})
	}

	return plugin.AnalyzeResponse{Diagnostics: diagnostics}, nil
}

func (a *analyzer) AnalyzeStack(resources []plugin.AnalyzerStackResource) (plugin.AnalyzeResponse, error) {
	// TODO: surface the complete set of resources to the OPA rule, perhaps as a different property.
	//     We don't bother to re-run the rules here since we already analyzed all of them.
	return plugin.AnalyzeResponse{}, nil
}

func (a *analyzer) Remediate(r plugin.AnalyzerResource) (plugin.RemediateResponse, error) {
	// OPA analyzer does not support remediation
	return plugin.RemediateResponse{}, nil
}

func (a *analyzer) GetAnalyzerInfo() (plugin.AnalyzerInfo, error) {
	var policies []plugin.AnalyzerPolicyInfo
	for _, pol := range a.pack.Policies {
		var enforcementLevel apitype.EnforcementLevel
		if pol.Level == advisoryRule {
			enforcementLevel = apitype.Advisory
		} else {
			enforcementLevel = apitype.Mandatory
		}
		policies = append(policies, plugin.AnalyzerPolicyInfo{
			Name:             pol.Name,
			DisplayName:      pol.DisplayName,
			Description:      pol.Description,
			Message:          pol.Message,
			EnforcementLevel: enforcementLevel,
		})
	}
	return plugin.AnalyzerInfo{
		Name:        a.pack.Name,
		DisplayName: a.pack.DisplayName,
		Policies:    policies,
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
	// No configuration needed for now
	return nil
}

func (a *analyzer) Cancel(ctx context.Context) error {
	// No cancellation needed
	return nil
}

func (a *analyzer) Close() error {
	// No resources to close
	return nil
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
	obj["__name"] = r.Name

	// Add resource options.
	opts := map[string]any{
		"protect":                 r.Options.Protect,
		"ignoreChanges":           r.Options.IgnoreChanges,
		"deleteBeforeReplace":     r.Options.DeleteBeforeReplace,
		"additionalSecretOutputs": propertyKeysToStrings(r.Options.AdditionalSecretOutputs),
		"aliases":                 aliasURNsToStrings(r.Options.AliasURNs),
		"customTimeouts": map[string]any{
			"create": r.Options.CustomTimeouts.Create,
			"update": r.Options.CustomTimeouts.Update,
			"delete": r.Options.CustomTimeouts.Delete,
		},
		"parent": string(r.Options.Parent),
	}
	obj["options"] = opts

	// Add provider info if available.
	var providerInfo map[string]any
	if r.Provider != nil {
		providerInfo = map[string]any{
			"type":       string(r.Provider.Type),
			"name":       r.Provider.Name,
			"urn":        string(r.Provider.URN),
			"properties": r.Provider.Properties.Mappable(),
		}
		obj["provider"] = providerInfo
	}

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
	if providerInfo != nil {
		obj["__provider"] = providerInfo
	}

	return obj
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
