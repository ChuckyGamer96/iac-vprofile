module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.19.1"

  cluster_name    = local.cluster_name
  cluster_version = "1.27"

  vpc_id                                       = module.vpc.vpc_id
  subnet_ids                                   = module.vpc.public_subnets
  cluster_endpoint_public_access               = false
  node_security_group_enable_recommended_rules = false
  cluster_endpoint_public_access_cidrs         = ["10.0.0.0/16"]
  cluster_enabled_log_types                    = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  node_security_group_additional_rules = {
    egress_all_custom = {
      description = "restricted egres"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      type        = "egress"
      cidr_blocks = ["10.0.0.0/16"]
    }
  }
  tags = {
    Environment = "2node-risks-1"
  }

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"

  }

  eks_managed_node_groups = {
    one = {
      name = "node-group-1"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }

    two = {
      name = "node-group-2"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 2
      desired_size = 1
    }

    #three = {
    #  name = "node-group-3"

    #  instance_types = ["t3.small"]

    #  min_size     = 1
    #  max_size     = 2
    #  desired_size = 1
    #}

    #four = {
    #  name = "node-group-4"

    #  instance_types = ["t3.small"]

    #  min_size     = 1
    #  max_size     = 2
    #  desired_size = 1
    #}
  }
}
