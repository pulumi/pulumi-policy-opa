# METADATA
# title: Kubernetes Security Policies
# scope: package
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

# METADATA
# title: Require Kubernetes Recommended Labels
# description: Deployments must include the standard Kubernetes recommended labels.
# custom:
#   message: Add the recommended labels to the Deployment metadata.
warn[msg] {
    input.kind == "Deployment"
    not labels
    msg = sprintf("%s must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels ", [name])
}

# METADATA
# title: Trusted Container Registry
# description: Pod container images must come from the trusted registry.
# custom:
#   message: Use an image from hooli.com/ instead.
deny[msg] {
    input.kind == "Pod"
    image := input.spec.containers[_].image
    not startswith(image, "hooli.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}

# METADATA
# title: Protect Production Resources
# description: Resources with 'prod' in the name must have protect enabled.
deny_protect_prod[msg] {
    contains(lower(input.__name), "prod")
    not input.options.protect
    msg := sprintf("Production resource '%s' must have protect enabled", [input.__name])
}
