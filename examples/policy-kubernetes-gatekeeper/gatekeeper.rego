# METADATA
# title: Kubernetes Gatekeeper Policies
# scope: package
package gatekeeper

import rego.v1

# This file demonstrates reusing OPA Gatekeeper constraint template rules
# with Pulumi. When `inputFormat: kubernetes-admission` is set in PulumiPolicy.yaml,
# Pulumi wraps Kubernetes resources in the Gatekeeper AdmissionReview structure
# so these rules work without modification.

# METADATA
# title: Require App Label
# description: All Kubernetes resources must have an "app" label.
# custom:
#   message: Add an "app" label to the resource metadata.
violation contains {"msg": msg} if {
    not input.review.object.metadata.labels["app"]
    msg := sprintf("%s '%s' is missing required label: app",
        [input.review.kind.kind, input.review.name])
}

# METADATA
# title: Disallow Latest Tag
# description: Container images must not use the "latest" tag.
# custom:
#   message: Pin the container image to a specific version tag.
deny contains msg if {
    container := input.review.object.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("container '%s' uses the 'latest' tag — pin to a specific version",
        [container.name])
}
