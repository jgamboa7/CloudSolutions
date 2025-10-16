provider "aws" {
  region = var.region
}

# Filter out local zones, which are not currently supported 
# with managed node groups
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = "CloudSolutions-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 5
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name = "CloudSolutions-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  enable_dns_hostnames   = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_destination_type            = "cloud-watch-logs"

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  vpc_flow_log_tags = {
    project = "cloudsolution"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.3.1"

  name               = local.cluster_name
  kubernetes_version = "1.33"

  endpoint_public_access = true
  # endpoint_public_access_cidrs           = []
  enable_cluster_creator_admin_permissions = true

  create_cloudwatch_log_group = true

  addons = {
    coredns = {}

    eks-pod-identity-agent = {
      before_compute = true
    }

    kube-proxy = {}

    vpc-cni = {
      before_compute           = true
      service_account_role_arn = module.irsa_vpc_cni.iam_role_arn
    }

    aws-ebs-csi-driver = {
      service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
    }

    snapshot-controller = {}

    amazon-cloudwatch-observability = {
      service_account_role_arn = module.irsa_cloudwatch_observability.iam_role_arn
    }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  node_security_group_additional_rules ={
    ingress_nodes_http={
      protocol                      = "tcp"
      from_port                     = 80
      to_port                       = 80
      type                          = "ingress"
      description                   = "Allow http traffic from node security group itself (for Pod-to-Pod communication)"
      self                          = true
    }
  }

  eks_managed_node_groups = {
    one = {
      name = "node-group-1"

      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }

    two = {
      name = "node-group-2"

      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }
  }

  # access_entries = {
  #   admin_access_entry = {
  #     principal_arn = var.eksAdmin
  #     type          = "STANDARD"

  #     policy_associations = {
  #       EKSAdminPolicy = {
  #         policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  #         access_scope = {
  #           type = "cluster"
  #         }
  #       }
  #     }
  #   }
  # }

}

data "aws_iam_policy" "vpc_cni_policy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

module "irsa_vpc_cni" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.39.0"

  create_role                   = true
  role_name                     = "AmazonEKS-VPC-CNI-Role-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.vpc_cni_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:aws-node"]
}

data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.39.0"

  create_role                   = true
  role_name                     = "AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
}

data "aws_iam_policy" "xray_write_only" {
  arn = "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess"
}

data "aws_iam_policy" "cw_agent_server" {
  arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

module "irsa_cloudwatch_observability" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.39.0"

  create_role                   = true
  role_name                     = "AmazonEKS_Observability_Role-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  oidc_fully_qualified_subjects = ["system:serviceaccount:amazon-cloudwatch:cloudwatch-agent"]

  role_policy_arns = [
    data.aws_iam_policy.xray_write_only.arn,
    data.aws_iam_policy.cw_agent_server.arn
  ]
}

resource "aws_sns_topic" "this" {
  name = "SNS-CloudSolution"
}

resource "aws_cloudwatch_log_group" "eks_observability" {
  name              = "/aws/eks/${module.eks.cluster_name}/workers-observability"
  retention_in_days = 120
}

resource "aws_cloudwatch_log_group" "container_insights_performance" {
  name              = "/aws/containerinsights/${module.eks.cluster_name}/performance"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "container_insights_application" {
  name              = "/aws/containerinsights/${module.eks.cluster_name}/application"
  retention_in_days = 14
}

locals {
  metric_transformation_name      = "ErrorCount"
  metric_transformation_namespace = "EKSControlPlane"
}

module "log_metric_filter" {
  source = "terraform-aws-modules/cloudwatch/aws//modules/log-metric-filter"

  log_group_name = aws_cloudwatch_log_group.eks_observability.name

  name    = "Metric-ControlPlaneErrors"
  pattern = "\"error\""

  metric_transformation_namespace = local.metric_transformation_namespace
  metric_transformation_name      = local.metric_transformation_name
}

module "alarm" {
  source = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"

  alarm_name          = "eks-controlplane-errors"
  alarm_description   = "EKS control plane errors detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 10
  period              = 300
  unit                = "Count"

  namespace   = local.metric_transformation_namespace
  metric_name = local.metric_transformation_name
  statistic   = "Sum"

  alarm_actions = [aws_sns_topic.this.arn]
}

resource "aws_cloudwatch_metric_alarm" "node_cpu_high" {
  alarm_name          = "eks-node-cpu-high"
  alarm_description   = "Average node CPU > 80% for 5 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 300
  threshold           = 80
  statistic           = "Average"

  namespace   = "ContainerInsights"
  metric_name = "node_cpu_utilization"
  dimensions = {
    ClusterName = module.eks.cluster_name
  }

  alarm_actions = [aws_sns_topic.this.arn]
}

resource "aws_cloudwatch_metric_alarm" "node_memory_high" {
  alarm_name          = "eks-node-memory-high"
  alarm_description   = "Average node memory > 80% for 5 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 300
  threshold           = 80
  statistic           = "Average"

  namespace   = "ContainerInsights"
  metric_name = "node_memory_utilization"
  dimensions = {
    ClusterName = module.eks.cluster_name
  }

  alarm_actions = [aws_sns_topic.this.arn]
}

resource "aws_cloudwatch_metric_alarm" "pod_restarts" {
  alarm_name          = "eks-pod-restarts"
  alarm_description   = "Pod restart count > 5 in 10 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  period              = 600
  threshold           = 5
  statistic           = "Sum"

  namespace   = "ContainerInsights"
  metric_name = "pod_restart_count"
  dimensions = {
    ClusterName = module.eks.cluster_name
  }

  alarm_actions = [aws_sns_topic.this.arn]
}

module "backup" {
  source  = "cloudposse/backup/aws"
  version = "1.1.0"

  backup_resources = []
  selection_tags = [
    {
      type  = "STRINGEQUALS"
      key   = "Backup"
      value = "true"
    }
  ]

  namespace        = "cs"
  stage            = "prod"
  name             = "backup"
  iam_role_name    = "BackUPRole_CloudSolutions"
  vault_name       = "CloudSolutions"
  plan_name_suffix = "CloudSolutions"

  rules = [
    {
      name              = "ebs-weekly"
      schedule          = "cron(0 1 ? * MON *)"
      start_window      = 360
      completion_window = 10080

      lifecycle = {
        # cold_storage_after = var.cold_storage_after
        delete_after = 35
      }
    }
  ]

}