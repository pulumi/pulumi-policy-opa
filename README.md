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
