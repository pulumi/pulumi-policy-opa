package azure

import future.keywords.if
import future.keywords.in

# SQL Server Policy: Require Azure AD authentication
warn[msg] {
    input.type == "azure-native:sql:Server"
    not input.administrators
    msg := sprintf("SQL Server '%s' should configure Azure AD authentication", [input.__name])
}

# SQL Server Policy: Require TDE for databases
deny[msg] {
    input.type == "azure-native:sql:Database"
    not input.transparentDataEncryption
    msg := sprintf("SQL Database '%s' must have Transparent Data Encryption enabled", [input.__name])
}

# SQL Server Policy: Require auditing
warn[msg] {
    input.type == "azure-native:sql:Server"
    not input.auditingSettings
    msg := sprintf("SQL Server '%s' should have auditing enabled", [input.__name])
}

# SQL Server Policy: Require Advanced Threat Protection
warn[msg] {
    input.type == "azure-native:sql:Server"
    not input.securityAlertPolicies
    msg := sprintf("SQL Server '%s' should have Advanced Threat Protection enabled", [input.__name])
}

# SQL Server Policy: No public network access
deny[msg] {
    input.type == "azure-native:sql:Server"
    input.publicNetworkAccess == "Enabled"
    contains(lower(input.__name), "prod")
    msg := sprintf("Production SQL Server '%s' should not allow public network access", [input.__name])
}

# SQL Database Policy: Require geo-redundant backup for production
deny[msg] {
    input.type == "azure-native:sql:Database"
    contains(lower(input.__name), "prod")
    input.storageAccountType == "LRS"
    msg := sprintf("Production SQL Database '%s' must use geo-redundant backup (not LRS)", [input.__name])
}
