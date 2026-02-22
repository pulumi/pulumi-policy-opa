package kubernetes

import rego.v1

# Labels: Require standard labels
required_labels = {
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/version",
    "app.kubernetes.io/component",
    "app.kubernetes.io/part-of",
    "app.kubernetes.io/managed-by"
}

deny contains msg if {
    input.kind == "Deployment"
    missing := required_labels - {label | input.metadata.labels[label]}
    count(missing) > 0
    msg := sprintf("Deployment '%s' must include Kubernetes recommended labels: %v", [name, missing])
}

deny contains msg if {
    input.kind == "Service"
    missing := required_labels - {label | input.metadata.labels[label]}
    count(missing) > 0
    msg := sprintf("Service '%s' must include Kubernetes recommended labels: %v", [name, missing])
}

# Labels: Environment label required
deny contains msg if {
    input.kind == "Deployment"
    not input.metadata.labels.environment
    msg := sprintf("Deployment '%s' must have 'environment' label", [name])
}

# Annotations: Production resources should have owner
warn contains msg if {
    input.metadata.labels.environment == "production"
    not input.metadata.annotations.owner
    msg := sprintf("%s '%s' in production should have 'owner' annotation", [input.kind, name])
}

# Annotations: Warn if no description
warn contains msg if {
    input.kind == "Deployment"
    not input.metadata.annotations.description
    msg := sprintf("Deployment '%s' should have 'description' annotation", [name])
}
