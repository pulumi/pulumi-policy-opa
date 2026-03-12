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
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
)

// makeResource is a helper that creates an AnalyzerResource with sensible defaults.
// Callers can override fields after creation.
func makeResource() plugin.AnalyzerResource {
	return plugin.AnalyzerResource{
		URN:  resource.URN("urn:pulumi:test-stack::test-project::aws:s3/bucket:Bucket::my-bucket"),
		Type: tokens.Type("aws:s3/bucket:Bucket"),
		Name: "my-bucket",
		Properties: resource.NewPropertyMapFromMap(map[string]any{
			"acl": "private",
			"serverSideEncryptionConfiguration": map[string]any{
				"rule": map[string]any{
					"applyServerSideEncryptionByDefault": map[string]any{
						"sseAlgorithm": "AES256",
					},
				},
			},
		}),
		Options: plugin.AnalyzerResourceOptions{},
	}
}

// makeStackResource is a helper that creates an AnalyzerStackResource with sensible defaults.
func makeStackResource(name, resType, urn string) plugin.AnalyzerStackResource {
	return plugin.AnalyzerStackResource{
		AnalyzerResource: plugin.AnalyzerResource{
			URN:  resource.URN(urn),
			Type: tokens.Type(resType),
			Name: name,
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "private",
			}),
			Options: plugin.AnalyzerResourceOptions{},
		},
	}
}

func TestBuildInput(t *testing.T) {
	t.Parallel()

	t.Run("IncludesProperties", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		input := buildOPAInput(r)

		if input["acl"] != "private" {
			t.Errorf("expected input[\"acl\"] = \"private\", got %v", input["acl"])
		}

		sse, ok := input["serverSideEncryptionConfiguration"].(map[string]any)
		if !ok {
			t.Fatal("expected serverSideEncryptionConfiguration to be a map")
		}
		rule, ok := sse["rule"].(map[string]any)
		if !ok {
			t.Fatal("expected rule to be a map")
		}
		defaults, ok := rule["applyServerSideEncryptionByDefault"].(map[string]any)
		if !ok {
			t.Fatal("expected applyServerSideEncryptionByDefault to be a map")
		}
		if defaults["sseAlgorithm"] != "AES256" {
			t.Errorf("expected sseAlgorithm = AES256, got %v", defaults["sseAlgorithm"])
		}
	})

	t.Run("IncludesType", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		input := buildOPAInput(r)

		if input["type"] != "aws:s3/bucket:Bucket" {
			t.Errorf("expected input[\"type\"] = \"aws:s3/bucket:Bucket\", got %v", input["type"])
		}
	})

	t.Run("IncludesURN", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		input := buildOPAInput(r)

		expected := "urn:pulumi:test-stack::test-project::aws:s3/bucket:Bucket::my-bucket"
		if input["urn"] != expected {
			t.Errorf("expected input[\"urn\"] = %q, got %v", expected, input["urn"])
		}
	})

	t.Run("IncludesName", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		input := buildOPAInput(r)

		if input["name"] != "my-bucket" {
			t.Errorf("expected input[\"name\"] = \"my-bucket\", got %v", input["name"])
		}
		if input["__name"] != "my-bucket" {
			t.Errorf("expected input[\"__name\"] = \"my-bucket\", got %v", input["__name"])
		}
	})

	t.Run("IncludesOptions", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		deleteBeforeReplace := true
		r.Options = plugin.AnalyzerResourceOptions{
			Protect:             true,
			IgnoreChanges:       []string{"tags", "description"},
			DeleteBeforeReplace: &deleteBeforeReplace,
			AdditionalSecretOutputs: []resource.PropertyKey{
				resource.PropertyKey("connectionString"),
			},
			AliasURNs: []resource.URN{
				resource.URN("urn:pulumi:stack::proj::type::old-name"),
			},
			Aliases: []resource.Alias{
				{
					URN:  resource.URN("urn:pulumi:stack::proj::type::old-alias"),
					Name: "old-alias",
					Type: "old:type",
				},
			},
			CustomTimeouts: resource.CustomTimeouts{
				Create: 300,
				Update: 120,
				Delete: 60,
			},
			Parent: resource.URN("urn:pulumi:stack::proj::type::parent-resource"),
		}

		input := buildOPAInput(r)

		opts, ok := input["options"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"options\"] to be a map")
		}

		if opts["protect"] != true {
			t.Errorf("expected options.protect = true, got %v", opts["protect"])
		}

		ignoreChanges, ok := opts["ignoreChanges"].([]string)
		if !ok {
			t.Fatal("expected options.ignoreChanges to be []string")
		}
		if len(ignoreChanges) != 2 || ignoreChanges[0] != "tags" || ignoreChanges[1] != "description" {
			t.Errorf("expected options.ignoreChanges = [\"tags\", \"description\"], got %v", ignoreChanges)
		}

		dbr, ok := opts["deleteBeforeReplace"].(*bool)
		if !ok {
			t.Fatal("expected options.deleteBeforeReplace to be *bool")
		}
		if dbr == nil || *dbr != true {
			t.Errorf("expected options.deleteBeforeReplace = true, got %v", opts["deleteBeforeReplace"])
		}

		secretOutputs, ok := opts["additionalSecretOutputs"].([]string)
		if !ok {
			t.Fatal("expected options.additionalSecretOutputs to be []string")
		}
		if len(secretOutputs) != 1 || secretOutputs[0] != "connectionString" {
			t.Errorf("expected additionalSecretOutputs = [\"connectionString\"], got %v", secretOutputs)
		}

		aliasURNs, ok := opts["aliasURNs"].([]string)
		if !ok {
			t.Fatal("expected options.aliasURNs to be []string")
		}
		if len(aliasURNs) != 1 || aliasURNs[0] != "urn:pulumi:stack::proj::type::old-name" {
			t.Errorf("expected aliasURNs = [\"urn:pulumi:stack::proj::type::old-name\"], got %v", aliasURNs)
		}

		aliases, ok := opts["aliases"].([]map[string]any)
		if !ok {
			t.Fatal("expected options.aliases to be []map[string]any")
		}
		if len(aliases) != 1 {
			t.Fatalf("expected 1 alias, got %d", len(aliases))
		}
		if aliases[0]["urn"] != "urn:pulumi:stack::proj::type::old-alias" {
			t.Errorf("expected alias.urn, got %v", aliases[0]["urn"])
		}
		if aliases[0]["name"] != "old-alias" {
			t.Errorf("expected alias.name = \"old-alias\", got %v", aliases[0]["name"])
		}
		if aliases[0]["type"] != "old:type" {
			t.Errorf("expected alias.type = \"old:type\", got %v", aliases[0]["type"])
		}

		timeouts, ok := opts["customTimeouts"].(map[string]any)
		if !ok {
			t.Fatal("expected options.customTimeouts to be a map")
		}
		if timeouts["create"] != float64(300) {
			t.Errorf("expected customTimeouts.create = 300, got %v", timeouts["create"])
		}
		if timeouts["update"] != float64(120) {
			t.Errorf("expected customTimeouts.update = 120, got %v", timeouts["update"])
		}
		if timeouts["delete"] != float64(60) {
			t.Errorf("expected customTimeouts.delete = 60, got %v", timeouts["delete"])
		}

		if opts["parent"] != "urn:pulumi:stack::proj::type::parent-resource" {
			t.Errorf("expected options.parent, got %v", opts["parent"])
		}
	})

	t.Run("IncludesProvider", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Provider = &plugin.AnalyzerProviderResource{
			URN:  resource.URN("urn:pulumi:stack::proj::pulumi:providers:aws::my-provider"),
			Type: tokens.Type("pulumi:providers:aws"),
			Name: "my-provider",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"region": "us-west-2",
			}),
		}

		input := buildOPAInput(r)

		prov, ok := input["provider"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"provider\"] to be a map")
		}
		if prov["type"] != "pulumi:providers:aws" {
			t.Errorf("expected provider.type = \"pulumi:providers:aws\", got %v", prov["type"])
		}
		if prov["name"] != "my-provider" {
			t.Errorf("expected provider.name = \"my-provider\", got %v", prov["name"])
		}
		if prov["urn"] != "urn:pulumi:stack::proj::pulumi:providers:aws::my-provider" {
			t.Errorf("expected provider.urn, got %v", prov["urn"])
		}

		provProps, ok := prov["properties"].(map[string]any)
		if !ok {
			t.Fatal("expected provider.properties to be a map")
		}
		if provProps["region"] != "us-west-2" {
			t.Errorf("expected provider.properties.region = \"us-west-2\", got %v", provProps["region"])
		}
	})

	t.Run("NilProvider", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Provider = nil

		input := buildOPAInput(r)

		prov, ok := input["provider"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"provider\"] to be an empty map when Provider is nil")
		}
		if len(prov) != 0 {
			t.Errorf("expected empty provider map, got %v", prov)
		}

		// __provider should also be present and empty.
		dprov, ok := input["__provider"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"__provider\"] to be an empty map when Provider is nil")
		}
		if len(dprov) != 0 {
			t.Errorf("expected empty __provider map, got %v", dprov)
		}
	})

	t.Run("EmptyOptions", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Options = plugin.AnalyzerResourceOptions{}

		input := buildOPAInput(r)

		opts, ok := input["options"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"options\"] to be a map")
		}

		if opts["protect"] != false {
			t.Errorf("expected options.protect = false, got %v", opts["protect"])
		}
		if opts["parent"] != "" {
			t.Errorf("expected options.parent = \"\", got %v", opts["parent"])
		}
		if opts["deleteBeforeReplace"] != (*bool)(nil) {
			t.Errorf("expected options.deleteBeforeReplace = nil, got %v", opts["deleteBeforeReplace"])
		}
	})

	t.Run("PropertiesBag", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		input := buildOPAInput(r)

		props, ok := input["properties"].(map[string]any)
		if !ok {
			t.Fatal("expected input[\"properties\"] to be a map")
		}

		// Properties should be accessible via the nested bag.
		if props["acl"] != "private" {
			t.Errorf("expected properties.acl = \"private\", got %v", props["acl"])
		}

		// The nested bag should NOT contain metadata keys.
		for _, key := range []string{"type", "urn", "__name", "options", "provider"} {
			if _, exists := props[key]; exists {
				t.Errorf("expected properties bag to not contain metadata key %q", key)
			}
		}

		// Top-level access should still work (backwards compatibility).
		if input["acl"] != "private" {
			t.Errorf("expected top-level acl = \"private\", got %v", input["acl"])
		}
	})

	t.Run("PropertiesBagCollision", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Properties = resource.NewPropertyMapFromMap(map[string]any{
			"properties": "some-value",
			"acl":        "private",
		})

		input := buildOPAInput(r)

		// The resource property "properties" should win over the metadata bag.
		if input["properties"] != "some-value" {
			t.Errorf("expected resource property to take precedence, got %v", input["properties"])
		}
	})

	t.Run("PropertyCollision", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Type = tokens.Type("aws:s3/bucket:Bucket")
		r.Properties = resource.NewPropertyMapFromMap(map[string]any{
			"type": "some-property-value",
			"acl":  "private",
		})

		input := buildOPAInput(r)

		// Resource property "type" should win over the metadata "type" at top level.
		if input["type"] != "some-property-value" {
			t.Errorf("expected resource property to take precedence, got %v", input["type"])
		}

		// The __type escape hatch should always return the metadata type.
		if input["__type"] != "aws:s3/bucket:Bucket" {
			t.Errorf("expected __type = \"aws:s3/bucket:Bucket\", got %v", input["__type"])
		}

		// Other properties should still be present.
		if input["acl"] != "private" {
			t.Errorf("expected acl = \"private\", got %v", input["acl"])
		}
	})

	t.Run("PrefixedMetadata", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Provider = &plugin.AnalyzerProviderResource{
			URN:  resource.URN("urn:pulumi:stack::proj::pulumi:providers:aws::my-provider"),
			Type: tokens.Type("pulumi:providers:aws"),
			Name: "my-provider",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"region": "us-west-2",
			}),
		}

		input := buildOPAInput(r)

		if input["__type"] != "aws:s3/bucket:Bucket" {
			t.Errorf("expected __type = \"aws:s3/bucket:Bucket\", got %v", input["__type"])
		}

		expectedURN := "urn:pulumi:test-stack::test-project::aws:s3/bucket:Bucket::my-bucket"
		if input["__urn"] != expectedURN {
			t.Errorf("expected __urn = %q, got %v", expectedURN, input["__urn"])
		}

		if input["__name"] != "my-bucket" {
			t.Errorf("expected __name = \"my-bucket\", got %v", input["__name"])
		}

		opts, ok := input["__options"].(map[string]any)
		if !ok {
			t.Fatal("expected __options to be a map")
		}
		if opts["protect"] != false {
			t.Errorf("expected __options.protect = false, got %v", opts["protect"])
		}

		props, ok := input["__properties"].(map[string]any)
		if !ok {
			t.Fatal("expected __properties to be a map")
		}
		if props["acl"] != "private" {
			t.Errorf("expected __properties.acl = \"private\", got %v", props["acl"])
		}

		prov, ok := input["__provider"].(map[string]any)
		if !ok {
			t.Fatal("expected __provider to be a map")
		}
		if prov["name"] != "my-provider" {
			t.Errorf("expected __provider.name = \"my-provider\", got %v", prov["name"])
		}
	})

	t.Run("EmptyProperties", func(t *testing.T) {
		t.Parallel()
		r := makeResource()
		r.Properties = resource.NewPropertyMapFromMap(map[string]any{})

		input := buildOPAInput(r)

		// Metadata fields should be present.
		if input["type"] != "aws:s3/bucket:Bucket" {
			t.Errorf("expected type field, got %v", input["type"])
		}
		if input["urn"] == nil {
			t.Error("expected urn field to be present")
		}
		if input["__name"] != "my-bucket" {
			t.Errorf("expected __name field, got %v", input["__name"])
		}
		if input["options"] == nil {
			t.Error("expected options field to be present")
		}
	})
}

func TestBuildStackInput(t *testing.T) {
	t.Parallel()

	t.Run("BasicResources", func(t *testing.T) {
		t.Parallel()
		resources := []plugin.AnalyzerStackResource{
			makeStackResource("bucket-1", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1"),
			makeStackResource("bucket-2", "aws:s3/bucket:Bucket",
				"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-2"),
		}

		input := buildStackOPAInput(resources)

		resList, ok := input["resources"].([]map[string]any)
		if !ok {
			t.Fatal("expected input[\"resources\"] to be []map[string]any")
		}
		if len(resList) != 2 {
			t.Fatalf("expected 2 resources, got %d", len(resList))
		}

		// Verify enriched fields on first resource.
		if resList[0]["__name"] != "bucket-1" {
			t.Errorf("expected __name = bucket-1, got %v", resList[0]["__name"])
		}
		if resList[0]["type"] != "aws:s3/bucket:Bucket" {
			t.Errorf("expected type = aws:s3/bucket:Bucket, got %v", resList[0]["type"])
		}
		if resList[0]["urn"] != "urn:pulumi:stack::proj::aws:s3/bucket:Bucket::bucket-1" {
			t.Errorf("expected correct urn, got %v", resList[0]["urn"])
		}
		if resList[0]["acl"] != "private" {
			t.Errorf("expected acl = private, got %v", resList[0]["acl"])
		}

		// Verify second resource.
		if resList[1]["__name"] != "bucket-2" {
			t.Errorf("expected __name = bucket-2, got %v", resList[1]["__name"])
		}
	})

	t.Run("IncludesDependencies", func(t *testing.T) {
		t.Parallel()
		sr := makeStackResource("my-instance", "aws:ec2/instance:Instance",
			"urn:pulumi:stack::proj::aws:ec2/instance:Instance::my-instance")
		sr.Dependencies = []resource.URN{
			resource.URN("urn:pulumi:stack::proj::aws:ec2/securityGroup:SecurityGroup::my-sg"),
			resource.URN("urn:pulumi:stack::proj::aws:ec2/subnet:Subnet::my-subnet"),
		}

		input := buildStackOPAInput([]plugin.AnalyzerStackResource{sr})

		resList := input["resources"].([]map[string]any)
		deps, ok := resList[0]["dependencies"].([]string)
		if !ok {
			t.Fatal("expected dependencies to be []string")
		}
		if len(deps) != 2 {
			t.Fatalf("expected 2 dependencies, got %d", len(deps))
		}
		if deps[0] != "urn:pulumi:stack::proj::aws:ec2/securityGroup:SecurityGroup::my-sg" {
			t.Errorf("unexpected dependency[0]: %s", deps[0])
		}
		if deps[1] != "urn:pulumi:stack::proj::aws:ec2/subnet:Subnet::my-subnet" {
			t.Errorf("unexpected dependency[1]: %s", deps[1])
		}
	})

	t.Run("IncludesPropertyDependencies", func(t *testing.T) {
		t.Parallel()
		sr := makeStackResource("my-instance", "aws:ec2/instance:Instance",
			"urn:pulumi:stack::proj::aws:ec2/instance:Instance::my-instance")
		sr.PropertyDependencies = map[resource.PropertyKey][]resource.URN{
			resource.PropertyKey("securityGroups"): {
				resource.URN("urn:pulumi:stack::proj::aws:ec2/securityGroup:SecurityGroup::sg-1"),
			},
			resource.PropertyKey("subnetId"): {
				resource.URN("urn:pulumi:stack::proj::aws:ec2/subnet:Subnet::subnet-1"),
			},
		}

		input := buildStackOPAInput([]plugin.AnalyzerStackResource{sr})

		resList := input["resources"].([]map[string]any)
		propDeps, ok := resList[0]["propertyDependencies"].(map[string][]string)
		if !ok {
			t.Fatal("expected propertyDependencies to be map[string][]string")
		}
		if len(propDeps) != 2 {
			t.Fatalf("expected 2 property dependency entries, got %d", len(propDeps))
		}

		sgDeps, ok := propDeps["securityGroups"]
		if !ok || len(sgDeps) != 1 {
			t.Fatalf("expected 1 securityGroups dependency, got %v", sgDeps)
		}
		if sgDeps[0] != "urn:pulumi:stack::proj::aws:ec2/securityGroup:SecurityGroup::sg-1" {
			t.Errorf("unexpected securityGroups dependency: %s", sgDeps[0])
		}
	})

	t.Run("EmptyResources", func(t *testing.T) {
		t.Parallel()
		input := buildStackOPAInput([]plugin.AnalyzerStackResource{})

		resList, ok := input["resources"].([]map[string]any)
		if !ok {
			t.Fatal("expected input[\"resources\"] to be []map[string]any, not nil")
		}
		if len(resList) != 0 {
			t.Errorf("expected 0 resources, got %d", len(resList))
		}
	})

	t.Run("ParentOverride", func(t *testing.T) {
		t.Parallel()
		sr := makeStackResource("child", "aws:s3/bucket:Bucket",
			"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::child")
		sr.Options.Parent = resource.URN("urn:pulumi:stack::proj::type::options-parent")
		sr.Parent = resource.URN("urn:pulumi:stack::proj::type::stack-parent")

		input := buildStackOPAInput([]plugin.AnalyzerStackResource{sr})

		resList := input["resources"].([]map[string]any)
		opts := resList[0]["options"].(map[string]any)
		if opts["parent"] != "urn:pulumi:stack::proj::type::stack-parent" {
			t.Errorf("expected parent to be overridden to stack-parent, got %v", opts["parent"])
		}
	})

	t.Run("NilDependencies", func(t *testing.T) {
		t.Parallel()
		sr := makeStackResource("my-bucket", "aws:s3/bucket:Bucket",
			"urn:pulumi:stack::proj::aws:s3/bucket:Bucket::my-bucket")
		sr.Dependencies = nil
		sr.PropertyDependencies = nil

		input := buildStackOPAInput([]plugin.AnalyzerStackResource{sr})

		resList := input["resources"].([]map[string]any)
		if _, exists := resList[0]["dependencies"]; exists {
			t.Error("expected dependencies to be absent when nil")
		}
		if _, exists := resList[0]["propertyDependencies"]; exists {
			t.Error("expected propertyDependencies to be absent when nil")
		}
	})
}

func TestParseK8sTypeToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		token   string
		want    *k8sTypeInfo
	}{
		{
			name:  "apps/v1 Deployment",
			token: "kubernetes:apps/v1:Deployment",
			want:  &k8sTypeInfo{Group: "apps", Version: "v1", Kind: "Deployment"},
		},
		{
			name:  "core/v1 Pod (core maps to empty group)",
			token: "kubernetes:core/v1:Pod",
			want:  &k8sTypeInfo{Group: "", Version: "v1", Kind: "Pod"},
		},
		{
			name:  "networking.k8s.io/v1 NetworkPolicy",
			token: "kubernetes:networking.k8s.io/v1:NetworkPolicy",
			want:  &k8sTypeInfo{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},
		},
		{
			name:  "batch/v1 Job",
			token: "kubernetes:batch/v1:Job",
			want:  &k8sTypeInfo{Group: "batch", Version: "v1", Kind: "Job"},
		},
		{
			name:  "non-K8s AWS type",
			token: "aws:s3/bucket:Bucket",
			want:  nil,
		},
		{
			name:  "non-K8s Azure type",
			token: "azure:storage/account:Account",
			want:  nil,
		},
		{
			name:  "empty string",
			token: "",
			want:  nil,
		},
		{
			name:  "malformed - no kind separator",
			token: "kubernetes:apps/v1",
			want:  nil,
		},
		{
			name:  "malformed - no version",
			token: "kubernetes:apps:Deployment",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseK8sTypeToken(tc.token)
			if tc.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %+v, got nil", tc.want)
			}
			if got.Group != tc.want.Group {
				t.Errorf("Group: expected %q, got %q", tc.want.Group, got.Group)
			}
			if got.Version != tc.want.Version {
				t.Errorf("Version: expected %q, got %q", tc.want.Version, got.Version)
			}
			if got.Kind != tc.want.Kind {
				t.Errorf("Kind: expected %q, got %q", tc.want.Kind, got.Kind)
			}
		})
	}
}

func TestK8sTypeInfo_ApiVersion(t *testing.T) {
	t.Parallel()

	t.Run("WithGroup", func(t *testing.T) {
		t.Parallel()
		info := &k8sTypeInfo{Group: "apps", Version: "v1", Kind: "Deployment"}
		if got := info.apiVersion(); got != "apps/v1" {
			t.Errorf("expected apps/v1, got %s", got)
		}
	})

	t.Run("CoreGroup", func(t *testing.T) {
		t.Parallel()
		info := &k8sTypeInfo{Group: "", Version: "v1", Kind: "Pod"}
		if got := info.apiVersion(); got != "v1" {
			t.Errorf("expected v1, got %s", got)
		}
	})
}

// makeK8sResource creates an AnalyzerResource for a Kubernetes type.
func makeK8sResource(typeToken, name string, props map[string]any) plugin.AnalyzerResource {
	return plugin.AnalyzerResource{
		URN:        resource.URN("urn:pulumi:test-stack::test-project::" + typeToken + "::" + name),
		Type:       tokens.Type(typeToken),
		Name:       name,
		Properties: resource.NewPropertyMapFromMap(props),
		Options:    plugin.AnalyzerResourceOptions{},
	}
}

func TestBuildKubernetesAdmissionInput(t *testing.T) {
	t.Parallel()

	t.Run("BasicDeployment", func(t *testing.T) {
		t.Parallel()
		r := makeK8sResource("kubernetes:apps/v1:Deployment", "my-deploy", map[string]any{
			"metadata": map[string]any{
				"name":      "my-deploy",
				"namespace": "default",
				"labels": map[string]any{
					"app": "web",
				},
			},
			"spec": map[string]any{
				"replicas": float64(3),
			},
		})

		k8sInfo := parseK8sTypeToken(string(r.Type))
		input := buildKubernetesAdmissionInput(r, k8sInfo, nil)

		review, ok := input["review"].(map[string]any)
		if !ok {
			t.Fatal("expected review to be a map")
		}

		// Check review.object has properties + synthesized fields.
		obj, ok := review["object"].(map[string]any)
		if !ok {
			t.Fatal("expected review.object to be a map")
		}
		if obj["apiVersion"] != "apps/v1" {
			t.Errorf("expected apiVersion = apps/v1, got %v", obj["apiVersion"])
		}
		if obj["kind"] != "Deployment" {
			t.Errorf("expected kind = Deployment, got %v", obj["kind"])
		}
		if obj["spec"] == nil {
			t.Error("expected spec to be present")
		}

		// Check review.kind GVK.
		kind, ok := review["kind"].(map[string]any)
		if !ok {
			t.Fatal("expected review.kind to be a map")
		}
		if kind["group"] != "apps" {
			t.Errorf("expected group = apps, got %v", kind["group"])
		}
		if kind["version"] != "v1" {
			t.Errorf("expected version = v1, got %v", kind["version"])
		}
		if kind["kind"] != "Deployment" {
			t.Errorf("expected kind = Deployment, got %v", kind["kind"])
		}

		// Check review.name and review.namespace.
		if review["name"] != "my-deploy" {
			t.Errorf("expected name = my-deploy, got %v", review["name"])
		}
		if review["namespace"] != "default" {
			t.Errorf("expected namespace = default, got %v", review["namespace"])
		}
		if review["operation"] != "CREATE" {
			t.Errorf("expected operation = CREATE, got %v", review["operation"])
		}

		// Check _pulumi metadata.
		pulumi, ok := input["_pulumi"].(map[string]any)
		if !ok {
			t.Fatal("expected _pulumi to be a map")
		}
		if pulumi["type"] != "kubernetes:apps/v1:Deployment" {
			t.Errorf("expected _pulumi.type, got %v", pulumi["type"])
		}
		if pulumi["name"] != "my-deploy" {
			t.Errorf("expected _pulumi.name = my-deploy, got %v", pulumi["name"])
		}
	})

	t.Run("CoreGroupPod", func(t *testing.T) {
		t.Parallel()
		r := makeK8sResource("kubernetes:core/v1:Pod", "my-pod", map[string]any{
			"metadata": map[string]any{
				"name": "my-pod",
			},
			"spec": map[string]any{},
		})

		k8sInfo := parseK8sTypeToken(string(r.Type))
		input := buildKubernetesAdmissionInput(r, k8sInfo, nil)
		review := input["review"].(map[string]any)
		obj := review["object"].(map[string]any)

		// Core group should produce apiVersion "v1" (no group prefix).
		if obj["apiVersion"] != "v1" {
			t.Errorf("expected apiVersion = v1, got %v", obj["apiVersion"])
		}

		kind := review["kind"].(map[string]any)
		if kind["group"] != "" {
			t.Errorf("expected empty group for core, got %v", kind["group"])
		}
	})

	t.Run("NoMetadata", func(t *testing.T) {
		t.Parallel()
		r := makeK8sResource("kubernetes:core/v1:ConfigMap", "my-cm", map[string]any{
			"data": map[string]any{"key": "value"},
		})

		k8sInfo := parseK8sTypeToken(string(r.Type))
		input := buildKubernetesAdmissionInput(r, k8sInfo, nil)
		review := input["review"].(map[string]any)

		// Name should fall back to r.Name when metadata is absent.
		if review["name"] != "my-cm" {
			t.Errorf("expected name = my-cm, got %v", review["name"])
		}
		if review["namespace"] != "" {
			t.Errorf("expected empty namespace, got %v", review["namespace"])
		}
	})

	t.Run("ExistingApiVersionPreserved", func(t *testing.T) {
		t.Parallel()
		r := makeK8sResource("kubernetes:apps/v1:Deployment", "my-deploy", map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "my-deploy"},
		})

		k8sInfo := parseK8sTypeToken(string(r.Type))
		input := buildKubernetesAdmissionInput(r, k8sInfo, nil)
		review := input["review"].(map[string]any)
		obj := review["object"].(map[string]any)

		// Should preserve existing values, not overwrite.
		if obj["apiVersion"] != "apps/v1" {
			t.Errorf("expected apiVersion preserved, got %v", obj["apiVersion"])
		}
		if obj["kind"] != "Deployment" {
			t.Errorf("expected kind preserved, got %v", obj["kind"])
		}
	})
}

func TestBuildKubernetesAdmissionStackInput(t *testing.T) {
	t.Parallel()

	t.Run("FiltersNonK8s", func(t *testing.T) {
		t.Parallel()
		resources := []plugin.AnalyzerStackResource{
			{AnalyzerResource: makeK8sResource("kubernetes:apps/v1:Deployment", "deploy", map[string]any{
				"metadata": map[string]any{"name": "deploy"},
			})},
			{AnalyzerResource: makeK8sResource("aws:s3/bucket:Bucket", "bucket", map[string]any{
				"acl": "private",
			})},
		}

		input := buildKubernetesAdmissionStackInput(resources)
		resList, ok := input["resources"].([]map[string]any)
		if !ok {
			t.Fatal("expected resources to be []map[string]any")
		}
		if len(resList) != 1 {
			t.Fatalf("expected 1 resource (non-K8s filtered), got %d", len(resList))
		}

		// The remaining resource should have admission format.
		if _, ok := resList[0]["review"]; !ok {
			t.Error("expected admission-format resource with review key")
		}
	})

	t.Run("EmptyWhenAllNonK8s", func(t *testing.T) {
		t.Parallel()
		resources := []plugin.AnalyzerStackResource{
			{AnalyzerResource: makeK8sResource("aws:s3/bucket:Bucket", "bucket", map[string]any{})},
		}

		input := buildKubernetesAdmissionStackInput(resources)
		resList := input["resources"].([]map[string]any)
		if len(resList) != 0 {
			t.Errorf("expected 0 resources, got %d", len(resList))
		}
	})
}
