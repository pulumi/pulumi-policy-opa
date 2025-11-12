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
