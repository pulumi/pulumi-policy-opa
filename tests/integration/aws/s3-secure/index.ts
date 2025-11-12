// Copyright 2025, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
