import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// This bucket should PASS all security policies
const secureBucket = new aws.s3.Bucket("secure-bucket", {
    acl: "private",
    serverSideEncryptionConfiguration: {
        rule: {
            applyServerSideEncryptionByDefault: {
                sseAlgorithm: "AES256",
            },
        },
    },
    versioning: {
        enabled: true,
    },
    loggings: [{
        targetBucket: "logs-bucket",
        targetPrefix: "s3-logs/",
    }],
});

// Block all public access
const publicAccessBlock = new aws.s3.BucketPublicAccessBlock("secure-bucket-public-access", {
    bucket: secureBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

export const bucketName = secureBucket.id;
