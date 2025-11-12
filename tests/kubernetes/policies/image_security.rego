package kubernetes

import future.keywords.if
import future.keywords.in

# Image: No latest tag
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    endswith(container.image, ":latest")
    msg := sprintf("%s '%s' container '%s' must not use :latest tag", [input.kind, name, container.name])
}

deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    not contains(container.image, ":")
    msg := sprintf("%s '%s' container '%s' must specify an image tag", [input.kind, name, container.name])
}

# Image: Must be from approved registry
allowed_registries = {
    "gcr.io",
    "docker.io",
    "quay.io",
    "registry.k8s.io"
}

warn[msg] {
    is_deployment_or_pod
    some container in input_containers
    registry := split(container.image, "/")[0]
    not registry in allowed_registries
    msg := sprintf("%s '%s' container '%s' uses image from non-approved registry: %s", [input.kind, name, container.name, registry])
}

# Image: Pull policy should be defined
warn[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.imagePullPolicy
    msg := sprintf("%s '%s' container '%s' should specify imagePullPolicy", [input.kind, name, container.name])
}

# Image: Always pull for production
warn[msg] {
    is_deployment_or_pod
    contains(lower(name), "prod")
    some container in input_containers
    container.imagePullPolicy != "Always"
    msg := sprintf("Production %s '%s' container '%s' should use imagePullPolicy: Always", [input.kind, name, container.name])
}
