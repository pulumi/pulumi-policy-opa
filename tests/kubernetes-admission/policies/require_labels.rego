# Gatekeeper-style policy requiring the "app" label on all resources.
# This uses the standard input.review.object structure from OPA Gatekeeper.
package kubernetes_admission

import rego.v1

violation contains {"msg": msg} if {
    not input.review.object.metadata.labels["app"]
    msg := sprintf("%s '%s' is missing required label: app", [input.review.kind.kind, input.review.name])
}
