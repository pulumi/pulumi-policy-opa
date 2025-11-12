#!/bin/bash

# Integration Test Runner for Pulumi OPA Policy Analyzer
# This script runs Pulumi preview with OPA policy packs

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    if ! command -v pulumi &> /dev/null; then
        echo -e "${RED}Error: Pulumi CLI is not installed${NC}"
        echo "Install Pulumi: https://www.pulumi.com/docs/get-started/install/"
        exit 1
    fi

    if ! command -v npm &> /dev/null; then
        echo -e "${RED}Error: npm is not installed${NC}"
        exit 1
    fi

    echo -e "${GREEN}Prerequisites OK${NC}"
    echo ""
}

# Build analyzer plugin
build_analyzer() {
    echo "Building OPA analyzer plugin..."
    cd ../..
    if ! go build -o pulumi-analyzer-policy-opa ./cmd/pulumi-analyzer-policy-opa; then
        echo -e "${RED}Failed to build analyzer${NC}"
        exit 1
    fi
    cd tests/integration
    echo -e "${GREEN}Analyzer built successfully${NC}"
    echo ""
}

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Run a single test
run_test() {
    local test_dir=$1
    local policy_pack=$2
    local should_pass=$3
    local test_name=$4

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo -e "${BLUE}Testing: $test_name${NC}"
    echo "  Directory: $test_dir"
    echo "  Policy Pack: $policy_pack"
    echo "  Expected: $([ "$should_pass" = "true" ] && echo "PASS" || echo "FAIL")"

    cd "$test_dir"

    # Install dependencies if needed
    if [ -f "package.json" ] && [ ! -d "node_modules" ]; then
        echo "  Installing dependencies..."
        npm install --silent > /dev/null 2>&1
    fi

    # Initialize Pulumi stack if needed
    if ! pulumi stack ls 2>/dev/null | grep -q "dev"; then
        echo "  Initializing stack..."
        pulumi stack init dev --non-interactive > /dev/null 2>&1 || true
    fi

    pulumi stack select dev --non-interactive > /dev/null 2>&1

    # Run pulumi preview with policy pack
    echo "  Running pulumi preview with OPA policy pack..."
    local preview_output
    local exit_code=0

    preview_output=$(pulumi preview --policy-pack "$policy_pack" --non-interactive 2>&1) || exit_code=$?

    # Check for policy violations
    local has_violations=false
    if echo "$preview_output" | grep -q "Policy Violations:"; then
        has_violations=true
    fi

    # Determine test result
    local test_passed=false
    if [ "$should_pass" = "true" ] && [ "$has_violations" = false ]; then
        test_passed=true
    elif [ "$should_pass" = "false" ] && [ "$has_violations" = true ]; then
        test_passed=true
    fi

    # Report result
    if [ "$test_passed" = true ]; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Expected violations: $should_pass"
        echo "  Got violations: $has_violations"
        echo ""
        echo "  Preview output:"
        echo "$preview_output" | grep -A 20 "Policy Violations:" || echo "$preview_output"
    fi

    cd - > /dev/null
    echo ""
}

# Main test execution
main() {
    echo "============================================"
    echo "Pulumi OPA Policy Integration Tests"
    echo "============================================"
    echo ""

    check_prerequisites
    build_analyzer

    # Get absolute path to policy packs
    AWS_POLICY_PACK="$(pwd)/../aws"
    AZURE_POLICY_PACK="$(pwd)/../azure"
    K8S_POLICY_PACK="$(pwd)/../kubernetes"

    echo "============================================"
    echo "AWS Tests"
    echo "============================================"

    if [ -d "aws/s3-secure" ]; then
        run_test "aws/s3-secure" "$AWS_POLICY_PACK" "true" "AWS S3 Secure Configuration"
    fi

    if [ -d "aws/s3-insecure" ]; then
        run_test "aws/s3-insecure" "$AWS_POLICY_PACK" "false" "AWS S3 Insecure Configuration"
    fi

    echo "============================================"
    echo "Kubernetes Tests"
    echo "============================================"

    if [ -d "kubernetes/secure-deployment" ]; then
        run_test "kubernetes/secure-deployment" "$K8S_POLICY_PACK" "true" "K8s Secure Deployment"
    fi

    if [ -d "kubernetes/insecure-deployment" ]; then
        run_test "kubernetes/insecure-deployment" "$K8S_POLICY_PACK" "false" "K8s Insecure Deployment"
    fi

    echo "============================================"
    echo "Test Summary"
    echo "============================================"
    echo "Total Tests:  $TOTAL_TESTS"
    echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
    echo ""

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}All integration tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some integration tests failed!${NC}"
        exit 1
    fi
}

# Run main
main "$@"
