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
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
)

// TestKubernetesAdmission_Integration loads the kubernetes-admission test pack
// and evaluates K8s resources through the full Analyze() path.
func TestKubernetesAdmission_Integration(t *testing.T) {
	t.Parallel()

	packDir := filepath.Join("..", "..", "tests", "kubernetes-admission", "policies")
	if _, err := os.Stat(packDir); os.IsNotExist(err) {
		t.Skipf("test pack not found at %s", packDir)
	}

	// loadPolicyPack needs the dir containing both PulumiPolicy.yaml and rego files.
	// The manifest is in the parent; copy setup into a temp dir that has both.
	dir := t.TempDir()

	// Copy PulumiPolicy.yaml.
	manifestSrc := filepath.Join("..", "..", "tests", "kubernetes-admission", "PulumiPolicy.yaml")
	manifest, err := os.ReadFile(manifestSrc)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PulumiPolicy.yaml"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}

	// Copy rego files.
	entries, err := os.ReadDir(packDir)
	if err != nil {
		t.Fatalf("reading policy dir: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".rego" {
			data, err := os.ReadFile(filepath.Join(packDir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	pack, e, err := loadPolicyPack(dir)
	if err != nil {
		t.Fatalf("loadPolicyPack failed: %v", err)
	}
	if pack.InputFormat != InputFormatKubernetesAdmission {
		t.Fatalf("expected kubernetes-admission input format, got %q", pack.InputFormat)
	}

	a := NewAnalyzer(pack, e)

	t.Run("K8sResourceWithLabelViolation", func(t *testing.T) {
		t.Parallel()
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:stack::proj::kubernetes:apps/v1:Deployment::bad-deploy"),
			Type: tokens.Type("kubernetes:apps/v1:Deployment"),
			Name: "bad-deploy",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"metadata": map[string]any{
					"name":   "bad-deploy",
					"labels": map[string]any{},
				},
				"spec": map[string]any{
					"replicas": float64(1),
				},
			}),
			Options: plugin.AnalyzerResourceOptions{},
		})
		if err != nil {
			t.Fatalf("Analyze failed: %v", err)
		}
		if len(resp.Diagnostics) == 0 {
			t.Error("expected violation for missing app label")
		}
		found := false
		for _, d := range resp.Diagnostics {
			if d.Message != "" {
				found = true
			}
		}
		if !found {
			t.Error("expected at least one diagnostic with a message")
		}
	})

	t.Run("K8sResourceValid", func(t *testing.T) {
		t.Parallel()
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:stack::proj::kubernetes:apps/v1:Deployment::good-deploy"),
			Type: tokens.Type("kubernetes:apps/v1:Deployment"),
			Name: "good-deploy",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"metadata": map[string]any{
					"name": "good-deploy",
					"labels": map[string]any{
						"app": "myapp",
					},
				},
				"spec": map[string]any{
					"replicas": float64(2),
				},
			}),
			Options: plugin.AnalyzerResourceOptions{},
		})
		if err != nil {
			t.Fatalf("Analyze failed: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected no violations for valid resource, got %d: %v",
				len(resp.Diagnostics), resp.Diagnostics)
		}
	})

	t.Run("NonK8sResourceSkipped", func(t *testing.T) {
		t.Parallel()
		resp, err := a.Analyze(plugin.AnalyzerResource{
			URN:  resource.URN("urn:pulumi:stack::proj::aws:s3/bucket:Bucket::my-bucket"),
			Type: tokens.Type("aws:s3/bucket:Bucket"),
			Name: "my-bucket",
			Properties: resource.NewPropertyMapFromMap(map[string]any{
				"acl": "public-read",
			}),
			Options: plugin.AnalyzerResourceOptions{},
		})
		if err != nil {
			t.Fatalf("Analyze failed: %v", err)
		}
		if len(resp.Diagnostics) != 0 {
			t.Errorf("expected non-K8s resource to be skipped, got %d diagnostics", len(resp.Diagnostics))
		}
	})
}
