package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// TestSuite represents a collection of policy tests
type TestSuite struct {
	Provider    string
	PolicyDir   string
	FixtureDir  string
	PackageName string
}

// TestCase represents a single test case
type TestCase struct {
	Name          string
	Fixture       map[string]interface{}
	ShouldViolate bool
}

// GetTestSuites returns all test suites
func GetTestSuites() []TestSuite {
	return []TestSuite{
		{
			Provider:    "AWS",
			PolicyDir:   "aws/policies",
			FixtureDir:  "aws/fixtures",
			PackageName: "aws",
		},
		{
			Provider:    "Azure",
			PolicyDir:   "azure/policies",
			FixtureDir:  "azure/fixtures",
			PackageName: "azure",
		},
		{
			Provider:    "Kubernetes",
			PolicyDir:   "kubernetes/policies",
			FixtureDir:  "kubernetes/fixtures",
			PackageName: "kubernetes",
		},
	}
}

// LoadFixture loads a JSON fixture file
func LoadFixture(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fixture map[string]interface{}
	if err := json.Unmarshal(data, &fixture); err != nil {
		return nil, err
	}

	return fixture, nil
}

// LoadPolicies loads all Rego policies from a directory
func LoadPolicies(dir string) (map[string]string, error) {
	modules := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".rego" {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			relPath, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}

			moduleName := strings.TrimSuffix(relPath, ".rego")
			modules[moduleName] = string(content)
		}

		return nil
	})

	return modules, err
}

// EvaluatePolicy evaluates a policy against input data
func EvaluatePolicy(modules map[string]string, packageName string, input map[string]interface{}) ([]interface{}, error) {
	// Compile modules
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, err
	}

	// Create rego query
	query := rego.New(
		rego.Query("data."+packageName+".deny"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Evaluate
	rs, err := query.Eval(nil)
	if err != nil {
		return nil, err
	}

	// Extract violations
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		if violations, ok := rs[0].Expressions[0].Value.([]interface{}); ok {
			return violations, nil
		}
	}

	return []interface{}{}, nil
}

// TestAWSPolicies tests AWS policies
func TestAWSPolicies(t *testing.T) {
	suite := TestSuite{
		Provider:    "AWS",
		PolicyDir:   "aws/policies",
		FixtureDir:  "aws/fixtures",
		PackageName: "aws",
	}

	runTestSuite(t, suite)
}

// TestAzurePolicies tests Azure policies
func TestAzurePolicies(t *testing.T) {
	suite := TestSuite{
		Provider:    "Azure",
		PolicyDir:   "azure/policies",
		FixtureDir:  "azure/fixtures",
		PackageName: "azure",
	}

	runTestSuite(t, suite)
}

// TestKubernetesPolicies tests Kubernetes policies
func TestKubernetesPolicies(t *testing.T) {
	suite := TestSuite{
		Provider:    "Kubernetes",
		PolicyDir:   "kubernetes/policies",
		FixtureDir:  "kubernetes/fixtures",
		PackageName: "kubernetes",
	}

	runTestSuite(t, suite)
}

// runTestSuite runs all tests for a test suite
func runTestSuite(t *testing.T, suite TestSuite) {
	t.Run(suite.Provider, func(t *testing.T) {
		// Load policies
		modules, err := LoadPolicies(suite.PolicyDir)
		if err != nil {
			t.Fatalf("Failed to load policies: %v", err)
		}

		if len(modules) == 0 {
			t.Skipf("No policies found in %s", suite.PolicyDir)
		}

		// Find all fixture files
		fixtures, err := filepath.Glob(filepath.Join(suite.FixtureDir, "*.json"))
		if err != nil {
			t.Fatalf("Failed to find fixtures: %v", err)
		}

		if len(fixtures) == 0 {
			t.Skipf("No fixtures found in %s", suite.FixtureDir)
		}

		// Test each fixture
		for _, fixturePath := range fixtures {
			filename := filepath.Base(fixturePath)
			shouldViolate := strings.Contains(filename, "invalid")

			t.Run(filename, func(t *testing.T) {
				// Load fixture
				fixture, err := LoadFixture(fixturePath)
				if err != nil {
					t.Fatalf("Failed to load fixture: %v", err)
				}

				// Evaluate policy
				violations, err := EvaluatePolicy(modules, suite.PackageName, fixture)
				if err != nil {
					t.Fatalf("Policy evaluation failed: %v", err)
				}

				hasViolations := len(violations) > 0

				// Check expectations
				if shouldViolate && !hasViolations {
					t.Errorf("Expected violations for %s but got none", filename)
				} else if !shouldViolate && hasViolations {
					t.Errorf("Expected no violations for %s but got: %v", filename, violations)
				}

				// Log violations for debugging
				if hasViolations {
					t.Logf("Violations found: %v", violations)
				}
			})
		}
	})
}

// BenchmarkPolicyEvaluation benchmarks policy evaluation
func BenchmarkPolicyEvaluation(b *testing.B) {
	suites := GetTestSuites()

	for _, suite := range suites {
		b.Run(suite.Provider, func(b *testing.B) {
			// Load policies
			modules, err := LoadPolicies(suite.PolicyDir)
			if err != nil {
				b.Fatalf("Failed to load policies: %v", err)
			}

			// Load a fixture
			fixtures, err := filepath.Glob(filepath.Join(suite.FixtureDir, "*_valid.json"))
			if err != nil || len(fixtures) == 0 {
				b.Skip("No fixtures found")
			}

			fixture, err := LoadFixture(fixtures[0])
			if err != nil {
				b.Fatalf("Failed to load fixture: %v", err)
			}

			// Benchmark
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := EvaluatePolicy(modules, suite.PackageName, fixture)
				if err != nil {
					b.Fatalf("Evaluation failed: %v", err)
				}
			}
		})
	}
}
