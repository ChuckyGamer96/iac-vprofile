package terraform.security

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_eks_cluster"
  after := rc.change.after
  some cfg in after.vpc_config
  cfg.endpoint_public_access == true
  msg := "EKS cluster has public endpoint access enabled"
}

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_eks_cluster"
  after := rc.change.after
  some cfg in after.vpc_config
  some cidr in cfg.public_access_cidrs
  cidr == "0.0.0.0/0"
  msg := "EKS cluster allows public access from 0.0.0.0/0"
}

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_security_group_rule"
  after := rc.change.after
  after.type == "egress"
  some cidr in after.cidr_blocks
  cidr == "0.0.0.0/0"
  msg := sprintf("Security group rule %s allows public egress to 0.0.0.0/0", [rc.address])
}