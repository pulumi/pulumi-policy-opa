package metadata

import rego.v1

# Production resources must be protected
deny contains msg if {
    contains(lower(input.__name), "prod")
    not input.options.protect
    msg := sprintf("Production resource '%s' (type: %s) must have protect enabled", [input.__name, input.type])
}

# Resources must have a parent
deny contains msg if {
    input.options.parent == ""
    msg := sprintf("Resource '%s' must specify a parent", [input.__name])
}

# Warn if provider is default
warn contains msg if {
    input.provider
    contains(input.provider.name, "default")
    msg := sprintf("Resource '%s' is using the default provider", [input.__name])
}
