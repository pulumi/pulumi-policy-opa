package main

import (
	"context"

	pbempty "github.com/golang/protobuf/ptypes/empty"
	pbstruct "github.com/golang/protobuf/ptypes/struct"

	"github.com/pulumi/pulumi/pkg/resource/provider"
	pulumirpc "github.com/pulumi/pulumi/sdk/proto/go"
)

const Version = "0.0.1" // TODO: load this from a linker-generated version.

// analyzer implements the gRPC interface needed to plug into Pulumi as a policy analyzer.
type analyzer struct {
	host *provider.HostClient
	pack *policyPack
	e    *evaler
}

func NewAnalyzer(host *provider.HostClient, pack *policyPack, e *evaler) pulumirpc.AnalyzerServer {
	return &analyzer{
		host: host,
		pack: pack,
		e:    e,
	}
}

func (a *analyzer) Analyze(ctx context.Context, req *pulumirpc.AnalyzeRequest) (*pulumirpc.AnalyzeResponse, error) {
	var diagnostics []*pulumirpc.AnalyzeDiagnostic

	// Run the policy pack against this object's metadata.
	// TODO: to attain rule compatibility with OPA rules written for, say, the Kubernetes Admission
	//     Controller, there is a very different schem we would need to follow. It's possible we should
	//     make the schema translation pluggable and customizable for certain policy packs and/or providers.
	obj := pbStructToGo(req.Properties)
	results, err := a.e.evalPolicyPack(ctx, a.pack, obj)
	if err != nil {
		return nil, err
	}

	// Translate the policy results into the appropriate analyzer RPC data structures.
	for _, result := range results {
		var level pulumirpc.EnforcementLevel
		if result.level == advisoryRule {
			level = pulumirpc.EnforcementLevel_ADVISORY
		} else {
			level = pulumirpc.EnforcementLevel_MANDATORY
		}
		diagnostics = append(diagnostics, &pulumirpc.AnalyzeDiagnostic{
			PolicyName:        result.rule,
			PolicyPackName:    result.pack,
			PolicyPackVersion: Version,
			Message:           result.msg,
			Urn:               req.Urn,
			EnforcementLevel:  level,
			// TODO: Description, Tags, EnforcementLevel
		})
	}

	return &pulumirpc.AnalyzeResponse{Diagnostics: diagnostics}, nil
}

func (a *analyzer) AnalyzeStack(ctx context.Context, req *pulumirpc.AnalyzeStackRequest) (*pulumirpc.AnalyzeResponse, error) {
	// TODO: surface the complete set of resources to the OPA rule, perhaps as a different property.
	//     We don't bother to re-run the rules here since we already analyzed all of them.
	return &pulumirpc.AnalyzeResponse{}, nil
}

func (a *analyzer) GetAnalyzerInfo(ctx context.Context, req *pbempty.Empty) (*pulumirpc.AnalyzerInfo, error) {
	var policies []*pulumirpc.PolicyInfo
	for _, pol := range a.pack.Policies {
		policies = append(policies, &pulumirpc.PolicyInfo{
			Name:             pol.Name,
			DisplayName:      pol.DisplayName,
			Description:      pol.Description,
			Message:          pol.Message,
			EnforcementLevel: pulumirpc.EnforcementLevel(pol.Level),
		})
	}
	return &pulumirpc.AnalyzerInfo{
		Name:        a.pack.Name,
		DisplayName: a.pack.DisplayName,
		Policies:    policies,
	}, nil
}

func (a *analyzer) GetPluginInfo(ctx context.Context, req *pbempty.Empty) (*pulumirpc.PluginInfo, error) {
	return &pulumirpc.PluginInfo{Version: Version}, nil
}

// pbStructToGo converts a Protobuf struct to a Go map.
func pbStructToGo(s *pbstruct.Struct) map[string]interface{} {
	if s == nil {
		return nil
	}

	m := make(map[string]interface{})
	for k, v := range s.Fields {
		m[k] = pbValueToGo(v)
	}
	return m
}

// structValueToIface converts a Protobuf value to its Go equivalent.
func pbValueToGo(v *pbstruct.Value) interface{} {
	switch k := v.Kind.(type) {
	case *pbstruct.Value_BoolValue:
		return k.BoolValue
	case *pbstruct.Value_ListValue:
		var a []interface{}
		for _, e := range k.ListValue.Values {
			a = append(a, pbValueToGo(e))
		}
		return a
	case *pbstruct.Value_NullValue:
		return nil
	case *pbstruct.Value_NumberValue:
		return k.NumberValue
	case *pbstruct.Value_StringValue:
		return k.StringValue
	case *pbstruct.Value_StructValue:
		return pbStructToGo(k.StructValue)
	default:
		return nil
	}
}
