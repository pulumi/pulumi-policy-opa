PROJECT_NAME := Pulumi Policy OPA Bridge
include build/common.mk

PROJECT          := github.com/pulumi/pulumi-policy-opa/cmd/pulumi-analyzer-policy-opa
GOPKGS           := $(shell go list ./... | grep -v /vendor/)
TESTPARALLELISM  := 10
VERSION          := $(shell ./scripts/get-version)
LDFLAGS          := -ldflags "-X main.VersionString=$(VERSION)"

build::
	go build $(LDFLAGS) ${PROJECT}

install::
	go install $(LDFLAGS) ${PROJECT}

lint::
	golangci-lint run

test_all::
	$(GO_TEST) ${GOPKGS}
