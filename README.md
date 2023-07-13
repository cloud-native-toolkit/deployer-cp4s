# Techzone Deployer Cloud Pak for Security pipelines

This repository contains a set of Tekton pipelines to deploy IBM Cloud Pak for Security in an IBM Technology Zone `deployer` cluster.

## Prerequisites
You will need an instance of [IBM Verify](https://www.ibm.com/products/verify-identity). Once you have an instance of verify, you will need the API access. Grab the Client ID and Client secret for Verify. More info can be found [here](https://www.ibm.com/docs/en/cloud-paks/cp-security/1.10?topic=providers-configuring-single-sign-sso-through-saml-authentication)
 
An IBM Technology Zone `deployer` cluster is assumed to be configured with an appropriate Red Hat OpenShift version for the Cloud Pak for Security version you wish to deploy, with appropriate sizing. Refer to [IBM Cloud Pak for Security documentation](https://www.ibm.com/docs/en/cloud-paks/cp-security/1.10) for more information.

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