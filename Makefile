PROJECT_NAME := Pulumi Policy OPA Bridge
include build/common.mk

PROJECT          := github.com/pulumi/pulumi-policy-opa/cmd/pulumi-analyzer-policy-opa
GOPKGS           := $(shell go list ./... | grep -v /vendor/)
TESTPARALLELISM  := 10
VERSION          := $(shell ./scripts/get-version)
LDFLAGS          := -ldflags "-X main.VersionString=$(VERSION)"

build::
	go build $(LDFLAGS) ${PROJECT}
	go build $(LDFLAGS) -o pulumi-language-opa ${PROJECT}

# The same binary doubles as the `opa` language plugin.
install::
	go install $(LDFLAGS) ${PROJECT}
	go build $(LDFLAGS) -o $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)/pulumi-language-opa ${PROJECT}

lint::
	golangci-lint run

test_all::
	$(GO_TEST) ${GOPKGS}
