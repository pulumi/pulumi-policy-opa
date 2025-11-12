package kubernetes

import future.keywords.if
import future.keywords.in

# Labels: Require standard labels
required_labels = {
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/version",
    "app.kubernetes.io/component",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/managed-by"
}

deny[msg] {
    input.kind == "Deployment"
    missing := required_labels - {label | input.metadata.labels[label]}
    count(missing) > 0
    msg := sprintf("Deployment '%s' must include Kubernetes recommended labels: %v", [name, missing])
}

deny[msg] {
    input.kind == "Service"
    missing := required_labels - {label | input.metadata.labels[label]}
    count(missing) > 0
    msg := sprintf("Service '%s' must include Kubernetes recommended labels: %v", [name, missing])
}

# Labels: Environment label required
deny[msg] {
    input.kind == "Deployment"
    not input.metadata.labels.environment
    msg := sprintf("Deployment '%s' must have 'environment' label", [name])
}

# Annotations: Production resources should have owner
warn[msg] {
    input.metadata.labels.environment == "production"
    not input.metadata.annotations.owner
    msg := sprintf("%s '%s' in production should have 'owner' annotation", [input.kind, name])
}

# Annotations: Warn if no description
warn[msg] {
    input.kind == "Deployment"
    not input.metadata.annotations.description
    msg := sprintf("Deployment '%s' should have 'description' annotation", [name])
}
