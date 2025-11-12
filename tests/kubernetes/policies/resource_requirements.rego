package kubernetes

import future.keywords.if
import future.keywords.in

# Resource Requirements: Must specify CPU limits
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.resources.limits.cpu
    msg := sprintf("%s '%s' container '%s' must specify CPU limits", [input.kind, name, container.name])
}

# Resource Requirements: Must specify memory limits
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.resources.limits.memory
    msg := sprintf("%s '%s' container '%s' must specify memory limits", [input.kind, name, container.name])
}

# Resource Requirements: Must specify CPU requests
warn[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.resources.requests.cpu
    msg := sprintf("%s '%s' container '%s' should specify CPU requests", [input.kind, name, container.name])
}

# Resource Requirements: Must specify memory requests
warn[msg] {
    is_deployment_or_pod
    some container in input_containers
    not container.resources.requests.memory
    msg := sprintf("%s '%s' container '%s' should specify memory requests", [input.kind, name, container.name])
}

# Resource Requirements: Requests should not exceed limits
deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    cpu_request := parse_cpu(container.resources.requests.cpu)
    cpu_limit := parse_cpu(container.resources.limits.cpu)
    cpu_request > cpu_limit
    msg := sprintf("%s '%s' container '%s' has CPU request exceeding limit", [input.kind, name, container.name])
}

deny[msg] {
    is_deployment_or_pod
    some container in input_containers
    mem_request := parse_memory(container.resources.requests.memory)
    mem_limit := parse_memory(container.resources.limits.memory)
    mem_request > mem_limit
    msg := sprintf("%s '%s' container '%s' has memory request exceeding limit", [input.kind, name, container.name])
}

# Helper to parse CPU (simplified)
parse_cpu(cpu) = result {
    endswith(cpu, "m")
    trimmed := trim_suffix(cpu, "m")
    result := to_number(trimmed)
}

parse_cpu(cpu) = result {
    not endswith(cpu, "m")
    result := to_number(cpu) * 1000
}

# Helper to parse memory (simplified)
parse_memory(mem) = result {
    endswith(mem, "Mi")
    trimmed := trim_suffix(mem, "Mi")
    result := to_number(trimmed)
}

parse_memory(mem) = result {
    endswith(mem, "Gi")
    trimmed := trim_suffix(mem, "Gi")
    result := to_number(trimmed) * 1024
}
