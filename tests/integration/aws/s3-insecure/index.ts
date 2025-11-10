import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// This bucket should FAIL security policies
const insecureBucket = new aws.s3.Bucket("insecure-bucket", {
    acl: "public-read",  // VIOLATION: public access
    // VIOLATION: No encryption
    // VIOLATION: No versioning
});

export const bucketName = insecureBucket.id;
