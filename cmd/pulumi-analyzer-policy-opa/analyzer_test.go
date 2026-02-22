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

// TestBuildInput_IncludesProperties verifies that resource properties appear at the
// top level of the input map.
func TestBuildInput_IncludesProperties(t *testing.T) {
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
}

// TestBuildInput_IncludesType verifies that the resource type is added to the input.
func TestBuildInput_IncludesType(t *testing.T) {
	r := makeResource()
	input := buildOPAInput(r)

	if input["type"] != "aws:s3/bucket:Bucket" {
		t.Errorf("expected input[\"type\"] = \"aws:s3/bucket:Bucket\", got %v", input["type"])
	}
}

// TestBuildInput_IncludesURN verifies that the resource URN is added to the input.
func TestBuildInput_IncludesURN(t *testing.T) {
	r := makeResource()
	input := buildOPAInput(r)

	expected := "urn:pulumi:test-stack::test-project::aws:s3/bucket:Bucket::my-bucket"
	if input["urn"] != expected {
		t.Errorf("expected input[\"urn\"] = %q, got %v", expected, input["urn"])
	}
}

// TestBuildInput_IncludesName verifies that the resource name is added as both
// "name" and "__name".
func TestBuildInput_IncludesName(t *testing.T) {
	r := makeResource()
	input := buildOPAInput(r)

	if input["name"] != "my-bucket" {
		t.Errorf("expected input[\"name\"] = \"my-bucket\", got %v", input["name"])
	}
	if input["__name"] != "my-bucket" {
		t.Errorf("expected input[\"__name\"] = \"my-bucket\", got %v", input["__name"])
	}
}

// TestBuildInput_IncludesOptions verifies that resource options are correctly serialized.
func TestBuildInput_IncludesOptions(t *testing.T) {
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
}

// TestBuildInput_IncludesProvider verifies that provider info is included when non-nil.
func TestBuildInput_IncludesProvider(t *testing.T) {
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
}

// TestBuildInput_NilProvider verifies that provider is an empty map when r.Provider is nil.
func TestBuildInput_NilProvider(t *testing.T) {
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
}

// TestBuildInput_EmptyOptions verifies that zero-value options are still present.
func TestBuildInput_EmptyOptions(t *testing.T) {
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
}

// TestBuildInput_PropertiesBag verifies that resource properties are also available
// under input["properties"] as a clean map without metadata keys mixed in.
func TestBuildInput_PropertiesBag(t *testing.T) {
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
}

// TestBuildInput_PropertiesBagCollision verifies that when a resource has a property
// named "properties", the resource property takes precedence (consistent with the
// general rule that resource properties win over metadata at the top level).
func TestBuildInput_PropertiesBagCollision(t *testing.T) {
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
}

// TestBuildInput_PropertyCollision verifies that resource properties take precedence
// over metadata fields with the same key name at the top level (backwards compatibility),
// and that __-prefixed metadata fields are always accessible as an escape hatch.
func TestBuildInput_PropertyCollision(t *testing.T) {
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
}

// TestBuildInput_PrefixedMetadata verifies that __-prefixed metadata fields are
// always present and contain the correct values regardless of property collisions.
func TestBuildInput_PrefixedMetadata(t *testing.T) {
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
}

// TestBuildInput_EmptyProperties verifies that with no properties, only metadata is present.
func TestBuildInput_EmptyProperties(t *testing.T) {
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
}
