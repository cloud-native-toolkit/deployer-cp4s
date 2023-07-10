# Techzone Deployer Cloud Pak for Securitypipelines

This repository contains a set of Tekton pipelines to deploy IBM Cloud Pak for Security in an IBM Technology Zone `deployer` cluster.

## Prerequisites

An IBM Technology Zone `deployer` cluster is assumed to be configured with an appropriate Red Hat OpenShift version for the Cloud Pak for Integration version you wish to deploy, with appropriate sizing. Refer to [IBM Cloud Pak for Integration documentation](https://www.ibm.com/docs/en/cloud-paks/cp-integration/2022.4) for more information.

A `deployer` cluster is configured with the following items:

- ExternalSecrets operator deployed with a ClusterSecretStore configured. The remote ExternalSecrets secret store must include an IBM Entitlement Key.
- Techzone Deployer Tekton tasks deployed ([deploy YAML](https://github.com/cloud-native-toolkit/deployer-tekton-tasks/blob/main/argocd.yaml)).
- OpenShift GitOps configured with [One Touch Provisioning ArgoCD instance](https://github.com/one-touch-provisioning/otp-gitops), and any relevant RBAC rules.
- OpenShift Pipelines operator deployed.
- OpenShift Data Foundation

## Repository organisation

The top-level folders in this repository are for the different CP4S versions. In each top-level folder there will be a pipeline and a pipelinerun.

```
.
└── cp4s-version/
    ├── pipeline.yaml
    └── pipeline-run.yaml
```

## Deployment Scripts

`oc apply -f pipeline.yaml` to install configure service account and install tasks and pipeline

`oc create -f pipeline-run.yaml` to kick off pipeline to install CP4S