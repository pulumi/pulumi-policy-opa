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
