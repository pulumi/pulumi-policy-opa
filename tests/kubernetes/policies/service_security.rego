package kubernetes

import rego.v1

# Service: No LoadBalancer for production without annotations
warn contains msg if {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    contains(lower(name), "prod")
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
    msg := sprintf("Production Service '%s' with type LoadBalancer should be internal", [name])
}

# Service: NodePort should be avoided
warn contains msg if {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := sprintf("Service '%s' uses NodePort, consider using LoadBalancer or Ingress instead", [name])
}

# Ingress: Require TLS
deny contains msg if {
    input.kind == "Ingress"
    contains(lower(name), "prod")
    not input.spec.tls
    msg := sprintf("Production Ingress '%s' must have TLS configured", [name])
}

deny contains msg if {
    input.kind == "Ingress"
    contains(lower(name), "prod")
    count(input.spec.tls) == 0
    msg := sprintf("Production Ingress '%s' must have TLS configured", [name])
}

# NetworkPolicy: Warn if no network policy for namespace
warn contains msg if {
    input.kind == "Deployment"
    contains(lower(name), "prod")
    # This would need additional context about NetworkPolicies in the namespace
    msg := sprintf("Consider creating NetworkPolicy for production Deployment '%s'", [name])
}
