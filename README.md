# Cloud Solutions Infrastructure

Cloud Solutions Inc., is expanding its infrastructure to support a new web application. The application requires a robust, scalable, and secure environment on AWS.

## Overview

This project implements an AWS infrastructure to host a global web application using Terraform.

It showcases best practices in:

* Cloud architecture design (compute, networking, storage, monitoring)
* Infrastructure as Code (Terraform)
* Security, observability, and automation

The solution is designed to meet production standards, emphasizing scalability, security, and reliability.

## Architecture
The infrastructure consists of:

* VPC with private and public subnets across 3 Availability Zones
* EKS Cluster for containerized workloads
* Load Balancer for traffic distribution
* EBS Persistent Volumes for stateful applications
* CloudWatch Observability Stack for logs, metrics, and alarms
* SNS Notifications for alerting and monitoring
* IAM Roles with least privilege access
* Terraform Remote State with S3

![Architecture_Diagram](./assets/img/CloudSolutionsArchitecture.png)

![k8s_Architecture_Diagram](./assets/img/k8sArchitecture.png)

## Key Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
|Infrastructure as Code | Terraform (requirement)| Enables versioned, consistent deployments across environments |
|Cluster Setup | AWS EKS | Managed Kubernetes control plane for scalability and resilience|
|Security | IAM with fine-grained policies | Limits resource access, enforces least-privilege principle |
|Secrets Management | AWS KMS + EKS Secrets Encryption + Key rotation | Ensures encryption of sensitive data at rest |
|Monitoring | CloudWatch + Container Insights + SNS | Unified monitoring and alerting pipeline|
|Backup Strategy | Tag-based snapshot automation | Simplifies backup management across tagged resources |
|Networking | Private worker nodes + public load balancer | Balances accessibility and security |
|State Management | S3 backend + locking | Prevents race conditions and supports team collaboration |
| CI/CD | GitHub workflows | Terraform plan + apply with PR approvals |

## Main Components

1. Networking
* Multi-AZ architecture
* Public & private subnets
* NAT Gateways for outbound internet access
* Route tables, security groups & NACLs
* Load Balancer
* Internet Gateway
* VPC flow logs

2. Compute (EKS Cluster)
* Managed EKS Control Plane
* Node Groups for scalable workloads
* Cluster logging enabled for api, audit, and authenticator
* Private endpoint access restricted via CIDR blocks
* Managed node groups
* CloudWatch Observability add-on

3. Storage (EBS + CSI Driver)
* EBS CSI driver installed via addon block
* PV manifests automatically provision EBS volumes
* Snapshot backup tagging supported via IAM role
* VolumeSnapshot manifest automatically provision volume backups

4. IAM & Security
* Least-privilege policies using aws_iam_policy_document
* Dedicated service roles for EKS, nodes, and CSI drivers
* Encryption enabled via KMS for EKS secrets + Key rotation

5. Monitoring & Alerts
* CloudWatch Log Groups for worker and control plane logs
* Metric filters for error detection
* SNS topic for alert notifications
Alarms:
* Node CPU utilization > 80%
* Node Memory utilization > 80%
* Pod restarts > 5 within 10 minutes
* Cluster Erros > 10 within 5 minutes

6. Backup & Recovery
* Tag-based EBS snapshot backups (Backup=true)
* Snapshot lifecycle policies for retention and cleanup
* EBS CSI Snapshot installed via addon block

## Deployment Instructions 
### Prerequisites
* AWS CLI configured with admin access
* Terraform >= 1.6
* kubectl & aws-iam-authenticator installed
* An S3 bucket for Terraform state backend block configuration
* Download [ALB NGINX ingress controller](https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.13.3/deploy/static/provider/cloud/deploy.yaml) and [ALB NGINX ingress controller for AWS](https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.13.3/deploy/static/provider/aws/nlb-with-tls-termination/deploy.yaml)

1. Clone the repository
```Bash
git clone https://github.com/jgamboa7/CloudSolutions.git
cd CloudSolutions
```
2. Initialize Terraform
```Bash
terraform init
```
3. Validate configuration
```Bash
terraform validate
```
4. Deploy Infrastructure
```Bash
terraform apply
```
5. Configure kubectl to connect to EKS cluster
```Bash
aws eks --region $(terraform output -raw region) update-kubeconfig \
  --name $(terraform output -raw cluster_name)
```
6. Verify connection
```Bash
kubectl cluster-info

Kubernetes control plane is running at https://39C56A779C40A0897CE68637AF41FC2A.gr7.eu-central-1.eks.amazonaws.com
CoreDNS is running at https://39C56A779C40A0897CE68637AF41FC2A.gr7.eu-central-1.eks.amazonaws.com/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```
```Bash
kubectl get nodes

NAME                                          STATUS   ROLES    AGE   VERSION
ip-10-0-1-172.eu-central-1.compute.internal   Ready    <none>   81m   v1.33.5-eks-113cf36
ip-10-0-1-7.eu-central-1.compute.internal     Ready    <none>   81m   v1.33.5-eks-113cf36
ip-10-0-2-153.eu-central-1.compute.internal   Ready    <none>   81m   v1.33.5-eks-113cf36
ip-10-0-3-118.eu-central-1.compute.internal   Ready    <none>   81m   v1.33.5-eks-113cf36
```
7. Install LB NGINX ingress controller
```Bash
cd nginx-ingress-controller
kubectl apply -f=controller-deploy.yaml -f=nlb-deploy.yaml
```
8. You have now provisioned an EKS cluster, configured kubectl, installed Nginx ingress controller and verified that your cluster is ready to use.

### CI/CD pipelines - terraform-plan.yml
This GitHub Actions workflow `(.github/workflows/terraform-plan.yml)` automatically runs a Terraform plan whenever a pull request is opened or updated on the main branch where any terraform files were modify.
It ensures that all infrastructure changes are formatted, validated, and reviewed before being merged.

The goal of this workflow is to:
* Enforce Terraform standards — formatting and validation checks.
* Preview infrastructure changes before deployment.
* Post the Terraform plan as a comment in the pull request for easy review.
* Ensure safety and consistency in infrastructure updates via automation.

1. Workflow Triggers
* A pull request targets the main branch.
* Manual trigger via workflow_dispatch.

2. Concurrency Control
* Prevents Multiples terraform jobs from running simultaneously. 
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
 
```
3. check-out the code by using `actions/checkout@v4`

4. Configure AWS Credentials by using `aws-actions/configure-aws-credentials@v4`

5. Setup terraform by using `hashicorp/setup-terraform@v3`

6. cache terraform provider by using `actions/cache@v4`

7. Terraform format checks
```Bash
terraform fmt -recursive -check
```
8. Initialize terraform
```Bash
terraform init
```
9. Validate terraform code
```Bash
terraform validate -no-color
```
10. terraform Plan
```Bash
terraform plan -input=false -no-color -out=tfplan
terraform show -no-color tfplan
```
11. Upload plan artifact by using `actions/upload-artifact@v4`

12. Add Plan Comment
If successful, the workflow posts a detailed comment on the pull request with:
* Results of each Terraform step (format, init, validate, plan)
* The full Terraform plan output (collapsed for readability)

13. Post Plan Failure
If the Terraform plan fails, an error summary is posted as a comment on the PR for debugging.

### CI/CD pipelines - terraform-apply.yml

This GitHub Actions workflow `(.github/workflows/terraform-apply.yml)` automatically applies Terraform infrastructure changes to production when manually triggered. It’s designed for controlled, auditable, and safe deployments of infrastructure-as-code in AWS.

The goal of this workflow is to:
* Ensure proper validation, planning, and logging of every change.
* Provide visibility via comments and uploaded logs.
* Prevent mistakes by referencing the run ID of the previous successful Plan workflow
* uses the exact binary plan file generated and reviewed in the Plan workflow. This guarantees that you deploy exactly what was planned, preventing configuration drift and unexpected changes.

1. Workflow Triggers
* The workflow only runs when explicitly triggered via the GitHub UI, ensuring human review occurred before execution.
* A push to `main` that affects `.tf` files.
* Manual trigger via workflow_dispatch.

2. Concurrency Control

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false
```

3. check-out the code by using `actions/checkout@v4`

4. Setup terraform by using `hashicorp/setup-terraform@v3`

5. cache terraform provider by using `actions/cache@v4`

6. Configure AWS Credentials by using `aws-actions/configure-aws-credentials@v4`

7. Initialize terraform
```Bash
terraform init -input=false -no-color
```
8. Download the reviewed terraform plan from a previous successful PR by using `actions/download-artifact@v4`

9. Display Terraform Plan

```Bash
terraform show ./tf-artifacts/tfplan > plan.txt 2>&1
```
10. Comment: No Changes - If the plan result is 0, a comment is added to the related PR or issue:

`“Terraform: No changes to apply (plan returned no changes).”`

11. Terraform Apply

`If the plan result is 2, the workflow applies the plan automatically:`

```Bash
terraform apply -input=false -no-color -auto-approve tfplan
```

12. Upload Apply Logs by using `actions/upload-artifact@v4`

13. Comment: Apply Result

14. Final Status Check

Scans the apply log for errors. If any errors are detected, the workflow fails — ensuring visibility in CI results.

## Production Safety Features

| Feature | Description |
|---------|-------------|
|Environment Protection|Runs under the `Staging` environment (Default value) in GitHub unless indicated otherwise |
|Exit Code Handling|Detects when no changes or errors occur to prevent unintended applies.|
|Artifact Storage|Stores full logs files for traceability.|
|PR Comments|Posts apply results to pull requests for full visibility.|
|Concurrency Group|Prevents simultaneous applies on the same branch.|

## Monitoring and Alerts

| Metric | Alarm Threshold | Action |
|--------|-----------------|--------|
|Node CPU Utilization|> 80% for 10 min|SNS notification|
|Node Memory Utilization|> 80% for 10 min|SNS notification|
|Pod Restarts|> 5 in 10 min|SNS notification|
|Control Plane Errors|>= 10 per 5 min|SNS notification|

## Security Highlights

* EKS secrets encrypted with KMS
* IAM least-privilege for EBS snapshot controller
* Cluster endpoint access restricted via CIDR
* Encrypted storage for EBS and S3
* No hardcoded credential

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.15 |
| <a name="requirement_cloudinit"></a> [cloudinit](#requirement\_cloudinit) | >= 2.3.7 |
| <a name="requirement_null"></a> [null](#requirement\_null) | >= 3.2.4 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | >= 0.9 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | >= 4.0 |

## Authors

Project created and maintained by [Jose Gamboa](https://github.com/jgamboa7)
