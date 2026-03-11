# METADATA
# title: AWS Security Policies
# scope: package
package aws

# ---- Resource-level policies ----

# METADATA
# title: No Public S3 Buckets
# description: S3 buckets must not use public-read or public-read-write ACLs.
# custom:
#   message: Set the ACL to 'private' or remove it entirely.
deny_public_buckets[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl in ["public-read", "public-read-write"]
    msg := sprintf("S3 bucket '%s' must not be publicly accessible", [input.__name])
}

# METADATA
# title: Require S3 Encryption
# description: All S3 buckets must have server-side encryption configured.
# custom:
#   message: Add a serverSideEncryptionConfiguration block.
deny_encryption[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [input.__name])
}

# METADATA
# title: Restrict EC2 Instance Size
# description: >
#   EC2 instances must not exceed the configured maximum instance size.
#   The maximum size is configurable via data.config.deny_large_instances.maxInstanceSize.
deny_large_instances[msg] {
    input.type == "aws:ec2/instance:Instance"
    max_size := data.config.deny_large_instances.maxInstanceSize
    blocked := {"m5.2xlarge", "m5.4xlarge", "m5.8xlarge", "m5.12xlarge", "m5.16xlarge", "m5.24xlarge"}
    blocked[input.instanceType]
    msg := sprintf("Instance '%s' type '%s' exceeds maximum allowed size '%s'",
                   [input.__name, input.instanceType, max_size])
}

# METADATA
# title: S3 Access Logging
# description: S3 buckets should have access logging enabled.
warn_logging[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.loggings
    msg := sprintf("S3 bucket '%s' should enable access logging", [input.__name])
}

# ---- Stack-level policies ----

# METADATA
# title: Maximum S3 Bucket Count
# description: Limits the number of S3 buckets per stack.
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}

# METADATA
# title: Stack-Wide Encryption
# description: All S3 buckets in the stack must have encryption enabled.
stack_deny_unencrypted_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    not r.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [r.__name])
}
