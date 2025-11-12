package aws

import future.keywords.if
import future.keywords.in

# S3 Bucket Policy: Deny public access
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not have public-read ACL for security compliance", [input.__name])
}

deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.acl == "public-read-write"
    msg := sprintf("S3 bucket '%s' must not have public-read-write ACL for security compliance", [input.__name])
}

# S3 Bucket Policy: Require encryption
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.serverSideEncryptionConfiguration
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [input.__name])
}

# S3 Bucket Policy: Require versioning for production
deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.versioning
    contains(lower(input.__name), "prod")
    msg := sprintf("Production S3 bucket '%s' must have versioning enabled", [input.__name])
}

deny[msg] {
    input.type == "aws:s3/bucket:Bucket"
    input.versioning.enabled == false
    contains(lower(input.__name), "prod")
    msg := sprintf("Production S3 bucket '%s' must have versioning enabled", [input.__name])
}

# S3 Bucket Policy: Require logging
warn[msg] {
    input.type == "aws:s3/bucket:Bucket"
    not input.loggings
    msg := sprintf("S3 bucket '%s' should have access logging enabled for audit trails", [input.__name])
}

# S3 Bucket Policy: Block public access
deny[msg] {
    input.type == "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
    not input.blockPublicAcls
    msg := sprintf("S3 bucket public access block '%s' must block public ACLs", [input.__name])
}

deny[msg] {
    input.type == "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
    input.blockPublicAcls == false
    msg := sprintf("S3 bucket public access block '%s' must block public ACLs", [input.__name])
}
