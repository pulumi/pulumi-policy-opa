package main

import (
	"context"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
)

const VersionString = "0.0.1" // TODO: load this from a linker-generated version.

// analyzer implements the Analyzer interface needed to plug into Pulumi as a policy analyzer.
type analyzer struct {
	pack *policyPack
	e    *evaler
}

func NewAnalyzer(pack *policyPack, e *evaler) plugin.Analyzer {
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

	// Run the policy pack against this object's metadata.
	// TODO: to attain rule compatibility with OPA rules written for, say, the Kubernetes Admission
	//     Controller, there is a very different schema we would need to follow. It's possible we should
	//     make the schema translation pluggable and customizable for certain policy packs and/or providers.
	obj := r.Properties.Mappable()
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

