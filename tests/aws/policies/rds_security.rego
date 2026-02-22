package aws

import rego.v1

# RDS Instance Policy: Require encryption at rest
deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    not input.storageEncrypted
    msg := sprintf("RDS instance '%s' must have storage encryption enabled", [input.__name])
}

deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    input.storageEncrypted == false
    msg := sprintf("RDS instance '%s' must have storage encryption enabled", [input.__name])
}

# RDS Instance Policy: No publicly accessible databases
deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    input.publiclyAccessible == true
    msg := sprintf("RDS instance '%s' must not be publicly accessible", [input.__name])
}

# RDS Instance Policy: Require automated backups
deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    input.backupRetentionPeriod == 0
    msg := sprintf("RDS instance '%s' must have automated backups enabled (retention > 0)", [input.__name])
}

# RDS Instance Policy: Minimum backup retention for production
deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    input.backupRetentionPeriod < 7
    contains(lower(input.__name), "prod")
    msg := sprintf("Production RDS instance '%s' must have at least 7 days backup retention", [input.__name])
}

# RDS Instance Policy: Require Multi-AZ for production
deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    not input.multiAz
    contains(lower(input.__name), "prod")
    msg := sprintf("Production RDS instance '%s' must have Multi-AZ enabled for high availability", [input.__name])
}

deny contains msg if {
    input.type == "aws:rds/instance:Instance"
    input.multiAz == false
    contains(lower(input.__name), "prod")
    msg := sprintf("Production RDS instance '%s' must have Multi-AZ enabled for high availability", [input.__name])
}

# RDS Instance Policy: Warn on deletion protection
warn contains msg if {
    input.type == "aws:rds/instance:Instance"
    not input.deletionProtection
    contains(lower(input.__name), "prod")
    msg := sprintf("Production RDS instance '%s' should have deletion protection enabled", [input.__name])
}
