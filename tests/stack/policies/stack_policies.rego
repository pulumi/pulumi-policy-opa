package stack

# Stack-level: limit the number of S3 buckets per stack
stack_deny_too_many_buckets[msg] {
    buckets := [r | r := input.resources[_]; r.type == "aws:s3/bucket:Bucket"]
    count(buckets) > 3
    msg := sprintf("Stack has %d S3 buckets, maximum allowed is 3", [count(buckets)])
}

# Stack-level: all S3 buckets must have encryption
stack_deny_unencrypted_buckets[msg] {
    r := input.resources[_]
    r.type == "aws:s3/bucket:Bucket"
    not r.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [r.__name])
}

# Stack-level: warn about security groups not referenced in dependencies
stack_warn_orphan_security_groups[msg] {
    sg := input.resources[_]
    sg.type == "aws:ec2/securityGroup:SecurityGroup"
    all_deps := {dep | r := input.resources[_]; dep := r.dependencies[_]}
    not all_deps[sg.urn]
    msg := sprintf("Security group '%s' is not referenced by any resource", [sg.__name])
}
