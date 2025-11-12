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

// This deployment should PASS all security policies
const deployment = new k8s.apps.v1.Deployment("nginx-secure", {
    metadata: {
        name: "nginx-deployment",
        labels: {
            "app.kubernetes.io/name": "nginx",
            "app.kubernetes.io/instance": "nginx-prod",
            "app.kubernetes.io/version": "1.21.0",
            "app.kubernetes.io/component": "web-server",
            "app.kubernetes.io/part-of": "web-app",
            "app.kubernetes.io/managed-by": "pulumi",
            "environment": "production",
        },
        annotations: {
            "owner": "platform-team",
            "description": "Production nginx web server",
        },
    },
    spec: {
        replicas: 3,
        selector: {
            matchLabels: {
                app: "nginx",
            },
        },
        template: {
            metadata: {
                labels: {
                    app: "nginx",
                },
            },
            spec: {
                containers: [{
                    name: "nginx",
                    image: "nginx:1.21.0",
                    imagePullPolicy: "Always",
                    ports: [{
                        containerPort: 80,
                    }],
                    resources: {
                        requests: {
                            cpu: "100m",
                            memory: "128Mi",
                        },
                        limits: {
                            cpu: "200m",
                            memory: "256Mi",
                        },
                    },
                    securityContext: {
                        runAsNonRoot: true,
                        runAsUser: 1000,
                        readOnlyRootFilesystem: true,
                        allowPrivilegeEscalation: false,
                        capabilities: {
                            drop: ["ALL"],
                        },
                    },
                }],
            },
        },
    },
});

export const deploymentName = deployment.metadata.name;
