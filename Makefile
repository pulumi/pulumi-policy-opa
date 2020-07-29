PROJECT_NAME := Pulumi Policy OPA Bridge
include build/common.mk

PROJECT          := github.com/pulumi/pulumi-policy-opa/cmd/pulumi-analyzer-policy-opa
GOPKGS           := $(shell go list ./... | grep -v /vendor/)
TESTPARALLELISM  := 10

build::
	go build ${PROJECT}

install::
	go install ${PROJECT}

lint::
	golangci-lint run

test_all::
	$(GO_TEST) ${GOPKGS}

.PHONY: check_clean_worktree
check_clean_worktree:
	$$(go env GOPATH)/src/github.com/pulumi/scripts/ci/check-worktree-is-clean.sh

# The travis_* targets are entrypoints for CI.
.PHONY: travis_cron travis_push travis_pull_request travis_api
travis_cron: all
travis_push: all check_clean_worktree only_test
travis_pull_request: all
travis_api: all
