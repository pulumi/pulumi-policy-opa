#!/bin/bash

# OPA Policy Test Runner
# Tests OPA policies against test fixtures

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if OPA is installed
if ! command -v opa &> /dev/null; then
    echo -e "${RED}Error: OPA is not installed${NC}"
    echo "Install OPA: https://www.openpolicyagent.org/docs/latest/#1-download-opa"
    exit 1
fi

echo "OPA Version: $(opa version)"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to test a policy against a fixture
test_policy() {
    local policy_dir=$1
    local fixture=$2
    local expected_result=$3  # "pass" or "fail"
    local test_name=$4

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo -n "Testing: $test_name ... "

    # Run OPA evaluation
    local result
    result=$(opa eval --bundle "$policy_dir" --input "$fixture" --format pretty "data" 2>&1)
    local exit_code=$?

    # Check for deny/violation rules
    local has_violations=false
    if echo "$result" | grep -q '"deny":\s*\['; then
        # Check if deny array is non-empty
        if ! echo "$result" | grep -q '"deny":\s*\[\s*\]'; then
            has_violations=true
        fi
    fi

    # Determine if test passed
    local test_passed=false
    if [ "$expected_result" = "pass" ] && [ "$has_violations" = false ]; then
        test_passed=true
    elif [ "$expected_result" = "fail" ] && [ "$has_violations" = true ]; then
        test_passed=true
    fi

    if [ "$test_passed" = true ]; then
        echo -e "${GREEN}PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Expected: $expected_result, Got violations: $has_violations"
        if [ "$has_violations" = true ]; then
            echo "$result" | grep -A 5 '"deny"'
        fi
    fi
}

echo "============================================"
echo "Testing AWS Policies"
echo "============================================"

if [ -d "aws/policies" ] && [ -d "aws/fixtures" ]; then
    # Test valid fixtures (should pass)
    for fixture in aws/fixtures/*_valid.json; do
        if [ -f "$fixture" ]; then
            test_policy "aws/policies" "$fixture" "pass" "AWS: $(basename $fixture)"
        fi
    done

    # Test invalid fixtures (should fail)
    for fixture in aws/fixtures/*_invalid*.json; do
        if [ -f "$fixture" ]; then
            test_policy "aws/policies" "$fixture" "fail" "AWS: $(basename $fixture)"
        fi
    done
fi

echo ""
echo "============================================"
echo "Testing Azure Policies"
echo "============================================"

if [ -d "azure/policies" ] && [ -d "azure/fixtures" ]; then
    # Test valid fixtures
    for fixture in azure/fixtures/*_valid.json; do
        if [ -f "$fixture" ]; then
            test_policy "azure/policies" "$fixture" "pass" "Azure: $(basename $fixture)"
        fi
    done

    # Test invalid fixtures
    for fixture in azure/fixtures/*_invalid*.json; do
        if [ -f "$fixture" ]; then
            test_policy "azure/policies" "$fixture" "fail" "Azure: $(basename $fixture)"
        fi
    done
fi

echo ""
echo "============================================"
echo "Testing Kubernetes Policies"
echo "============================================"

if [ -d "kubernetes/policies" ] && [ -d "kubernetes/fixtures" ]; then
    # Test valid fixtures
    for fixture in kubernetes/fixtures/*_valid.json; do
        if [ -f "$fixture" ]; then
            test_policy "kubernetes/policies" "$fixture" "pass" "K8s: $(basename $fixture)"
        fi
    done

    # Test invalid fixtures
    for fixture in kubernetes/fixtures/*_invalid*.json; do
        if [ -f "$fixture" ]; then
            test_policy "kubernetes/policies" "$fixture" "fail" "K8s: $(basename $fixture)"
        fi
    done
fi

echo ""
echo "============================================"
echo "Test Summary"
echo "============================================"
echo "Total Tests:  $TOTAL_TESTS"
echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
