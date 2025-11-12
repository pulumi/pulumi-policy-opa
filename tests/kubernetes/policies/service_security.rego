package kubernetes

import future.keywords.if
import future.keywords.in

# Service: No LoadBalancer for production without annotations
warn[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    contains(lower(name), "prod")
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
    msg := sprintf("Production Service '%s' with type LoadBalancer should be internal", [name])
}

# Service: NodePort should be avoided
warn[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := sprintf("Service '%s' uses NodePort, consider using LoadBalancer or Ingress instead", [name])
}

# Ingress: Require TLS
deny[msg] {
    input.kind == "Ingress"
    contains(lower(name), "prod")
    not input.spec.tls
    msg := sprintf("Production Ingress '%s' must have TLS configured", [name])
}

deny[msg] {
    input.kind == "Ingress"
    contains(lower(name), "prod")
    count(input.spec.tls) == 0
    msg := sprintf("Production Ingress '%s' must have TLS configured", [name])
}

# NetworkPolicy: Warn if no network policy for namespace
warn[msg] {
    input.kind == "Deployment"
    contains(lower(name), "prod")
    # This would need additional context about NetworkPolicies in the namespace
    msg := sprintf("Consider creating NetworkPolicy for production Deployment '%s'", [name])
}
