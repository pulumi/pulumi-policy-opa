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
import * as k8s from "@pulumi/kubernetes";

// This deployment should FAIL security policies
const deployment = new k8s.apps.v1.Deployment("app-insecure", {
    metadata: {
        name: "app-deployment",
        labels: {
            app: "myapp",  // VIOLATION: Missing required labels
        },
    },
    spec: {
        replicas: 2,
        selector: {
            matchLabels: {
                app: "myapp",
            },
        },
        template: {
            metadata: {
                labels: {
                    app: "myapp",
                },
            },
            spec: {
                containers: [{
                    name: "app",
                    image: "myapp:latest",  // VIOLATION: :latest tag
                    securityContext: {
                        privileged: true,  // VIOLATION: privileged container
                    },
                    // VIOLATION: No resource limits
                }],
            },
        },
    },
});

export const deploymentName = deployment.metadata.name;
