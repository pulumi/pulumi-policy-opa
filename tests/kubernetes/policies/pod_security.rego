package kubernetes

import future.keywords.if
import future.keywords.in

# Pod Security: No privileged containers
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    container.securityContext.privileged == true
    msg := sprintf("%s '%s' must not run privileged containers", [input.kind, name])
}

# Pod Security: Must drop ALL capabilities
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.securityContext.capabilities.drop
    msg := sprintf("%s '%s' must drop all capabilities", [input.kind, name])
}

deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    container.securityContext.capabilities.drop
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("%s '%s' must drop ALL capabilities", [input.kind, name])
}

# Pod Security: Must run as non-root
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    container.securityContext.runAsNonRoot == false
    msg := sprintf("%s '%s' container must not run as root", [input.kind, name])
}

# Pod Security: Must have read-only root filesystem
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("%s '%s' must have read-only root filesystem", [input.kind, name])
}

deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    container.securityContext.readOnlyRootFilesystem == false
    msg := sprintf("%s '%s' must have read-only root filesystem", [input.kind, name])
}

# Pod Security: Warn on host network
warn[msg] {
    is_deployment_or_pod
    input.spec.hostNetwork == true
    msg := sprintf("%s '%s' should not use host network", [input.kind, name])
}

# Pod Security: Warn on host PID
warn[msg] {
    is_deployment_or_pod
    input.spec.hostPID == true
    msg := sprintf("%s '%s' should not use host PID namespace", [input.kind, name])
}

# Pod Security: Warn on host IPC
warn[msg] {
    is_deployment_or_pod
    input.spec.hostIPC == true
    msg := sprintf("%s '%s' should not use host IPC namespace", [input.kind, name])
}

# Helper functions
is_deployment_or_pod {
    input.kind == "Deployment"
}

is_deployment_or_pod {
    input.kind == "Pod"
}

is_deployment_or_pod {
    input.kind == "StatefulSet"
}

is_deployment_or_pod {
    input.kind == "DaemonSet"
}

input_containers[container] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
}

input_containers[container] {
    input.kind == "StatefulSet"
    container := input.spec.template.spec.containers[_]
}

input_containers[container] {
    input.kind == "DaemonSet"
    container := input.spec.template.spec.containers[_]
}

input_containers[container] {
    input.kind == "Pod"
    container := input.spec.containers[_]
}

name = input.metadata.name
