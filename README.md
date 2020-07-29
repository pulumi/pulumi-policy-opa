# Pulumi Open Policy Agent (OPA) Bridge for CrossGuard

This project allows Open Policy Agent (OPA) rules to be run in the context of Pulumi's policy system, CrossGuard.

## How it works

Pulumi can enforce policies during a deployment. This includes during a "preview" -- before a deployment is attempted --
in addition to afterwards -- when certain other properties are known.

The OPA integration implements the Pulumi plugin interface for policies. Unlike Pulumi's standard approach to
implementing policy rules using [an SDK in a general purpose language](https://github.com/pulumi/pulumi-policy)
this bridge lets you leverage any existing OPA rule within the overall Pulumi CrossGuard system.

## How to build and distribute

The binary this repo builds is not intended to be run directly. It produces a plugin named `pulumi-policy-opa` which,
when packaged with a set of OPA rules in the `rules/` directory, can be loaded by the Pulumi plugin system.

First, build and install the OPA policy analyzer.

```
$ make install
INSTALL:
go install github.com/pulumi/pulumi-policy-opa/cmd/pulumi-analyzer-policy-opa
```

This will place `pulumi-analyzer-policy-opa` in your `GOBIN`.  If you haven't already - make sure `GOBIN` is in your `PATH`:

```
$ export PATH=$PATH:$(go env GOPATH)/bin
```

You can now use OPA policy packs.  Create a folder that contains two files - a `PulumiPolicy.yaml` and one or more `.rego` files.

```
$ cat PulumiPolicy.yaml 
description: A minimal Policy Pack for Kubernetes using OPA.
runtime: opa    

$ cat labels.rego 
package kubernetes

name = input.metadata.name

labels {
    input.metadata.labels["app.kubernetes.io/name"]
    input.metadata.labels["app.kubernetes.io/instance"]
    input.metadata.labels["app.kubernetes.io/version"]
    input.metadata.labels["app.kubernetes.io/component"]
    input.metadata.labels["app.kubernetes.io/part-of"]
    input.metadata.labels["app.kubernetes.io/managed-by"]
}

deny[msg] {
  input.kind = "Deployment"
  not labels
  msg = sprintf("%s must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels ", [name])
}
```

You can now run an update on a Pulumi program locally using `pulumi up --policy-pack <path_to_policy_folder>` passing the path to the folder you created in the previous step.

```
➜  app git:(master) ✗ pulumi up --policy-pack ../policy-kubernetes    
Previewing update (dev):
     Type                           Name                   Plan       Info
 +   pulumi:pulumi:Stack            simple-kubernetes-dev  create     1 error
 +   └─ kubernetes:apps:Deployment  nginx                  create     
 
Diagnostics:
  pulumi:pulumi:Stack (simple-kubernetes-dev):
    error: preview failed
 
Policy Violations:
    [mandatory]  kubernetes v0.0.1  deny (nginx: kubernetes:apps/v1:Deployment)
    nginx-me0llhgr must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels 
```

Note that the policy was implemented in `labels.rego` using the Rego langauge, but applied to the deployment of a Pulumi program written in TypeScript.  Note also that the policy was run *before* the resource was deployed, and failed the preview stage.  This allows OPA policies to be enforced very early in the development and deployment process - close to the developers creating the infrastructure - allowing for a quicker security and policy feedback loop for the cloud engineering team.