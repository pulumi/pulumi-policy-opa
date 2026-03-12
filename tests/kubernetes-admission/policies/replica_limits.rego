# Gatekeeper-style policy enforcing maximum replicas via input.parameters.
package kubernetes_admission

import rego.v1

violation contains {"msg": msg} if {
    input.review.object.spec.replicas > input.parameters.maxReplicas
    msg := sprintf("Deployment '%s' has %d replicas, max allowed is %d",
        [input.review.name, input.review.object.spec.replicas, input.parameters.maxReplicas])
}
