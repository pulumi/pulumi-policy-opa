package aws

import future.keywords.if
import future.keywords.in

# IAM Policy: No wildcard actions
deny[msg] {
    input.type == "aws:iam/policy:Policy"
    policy := json.unmarshal(input.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    statement.Action == "*"
    msg := sprintf("IAM policy '%s' grants wildcard (*) permissions which is overly permissive", [input.__name])
}

# IAM Policy: No wildcard resources for broad actions
deny[msg] {
    input.type == "aws:iam/policy:Policy"
    policy := json.unmarshal(input.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    statement.Resource == "*"
    not is_read_only_action(statement.Action)
    msg := sprintf("IAM policy '%s' grants permissions on all resources (*) for write actions", [input.__name])
}

# IAM Role Policy: Require MFA for assume role
warn[msg] {
    input.type == "aws:iam/role:Role"
    policy := json.unmarshal(input.assumeRolePolicy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    not statement.Condition.Bool["aws:MultiFactorAuthPresent"]
    msg := sprintf("IAM role '%s' should require MFA for assume role operations", [input.__name])
}

# IAM User Policy: Warn against creating IAM users (prefer roles)
warn[msg] {
    input.type == "aws:iam/user:User"
    msg := sprintf("Consider using IAM roles instead of user '%s' for better security practices", [input.__name])
}

# Helper function to check if action is read-only
is_read_only_action(action) {
    startswith(action, "Describe")
}

is_read_only_action(action) {
    startswith(action, "Get")
}

is_read_only_action(action) {
    startswith(action, "List")
}
