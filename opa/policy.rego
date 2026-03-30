package terraform.security

deny contains "EKS cluster has public endpoint access enabled" if {
  rc := input.resource_changes[_]
  rc.type == "aws_eks_cluster"
  rc.change.after.vpc_config[_].endpoint_public_access == true
}

deny contains "EKS cluster allows public access from 0.0.0.0/0" if {
  rc := input.resource_changes[_]
  rc.type == "aws_eks_cluster"
  rc.change.after.vpc_config[_].public_access_cidrs[_] == "0.0.0.0/0"
}

deny contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_security_group_rule"
  rc.change.after.type == "egress"
  rc.change.after.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Security group rule %s allows public egress to 0.0.0.0/0", [rc.address])
}