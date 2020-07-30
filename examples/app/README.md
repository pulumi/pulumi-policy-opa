## Build and test

```bash
$ pulumi stack init dev
Created stack 'dev'

$ pulumi up --policy-pack ../policy-kubernetes
Previewing update (dev):
     Type                           Name                   Plan       Info
 +   pulumi:pulumi:Stack            simple-kubernetes-dev  create     1 error
 +   └─ kubernetes:apps:Deployment  nginx                  create     
 
Diagnostics:
  pulumi:pulumi:Stack (simple-kubernetes-dev):
    error: preview failed
 
Policy Violations:
    [mandatory]  kubernetes v0.0.1  deny (nginx: kubernetes:apps/v1:Deployment)
    nginx-t6yfa9vr must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels 
```