#!/usr/bin/env python3

import json
import csv
import os
import sys
from typing import Any, Dict, List, Set

SENSITIVE_PORTS = {22, 21, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 27017}


def safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def flatten_actions(actions: Any) -> List[str]:
    result = []
    for item in safe_list(actions):
        if isinstance(item, list):
            result.extend([safe_str(x) for x in item])
        else:
            result.append(safe_str(item))
    return result


def flatten_resources(resources: Any) -> List[str]:
    result = []
    for item in safe_list(resources):
        if isinstance(item, list):
            result.extend([safe_str(x) for x in item])
        else:
            result.append(safe_str(item))
    return result


def get_after_values(change: Dict[str, Any]) -> Dict[str, Any]:
    after = change.get("after")
    if after is None:
        return {}
    return after


def is_public_cidr(cidr: str) -> bool:
    cidr = safe_str(cidr).strip()
    return cidr == "0.0.0.0/0" or cidr == "::/0"


def count_sensitive_ports(from_port: Any, to_port: Any) -> int:
    try:
        fp = int(from_port)
        tp = int(to_port)
    except (TypeError, ValueError):
        return 0

    found = 0
    for port in SENSITIVE_PORTS:
        if fp <= port <= tp:
            found += 1
    return found


def extract_features(plan_path: str) -> Dict[str, int]:
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    resource_changes = plan.get("resource_changes", [])

    features = {
        # Existing columns
        "resource_change_count": 0,
        "create_count": 0,
        "update_count": 0,
        "delete_count": 0,
        "eks_public_endpoint": 0,
        "eks_public_cidr_open": 0,
        "public_egress_rule": 0,
        "security_group_rule_count": 0,
        "iam_resource_count": 0,
        "network_resource_count": 0,

        # New columns
        "open_cidr_0_0_0_0": 0,
        "sensitive_port_open_count": 0,
        "internet_gateway_present": 0,
        "nat_gateway_present": 0,
        "public_subnet_count": 0,
        "iam_wildcard_action": 0,
        "iam_wildcard_resource": 0,
        "unencrypted_resources": 0,
        "logging_disabled": 0,
        "s3_public_access_disabled": 0,
        "load_balancer_public": 0,
    }

    iam_types: Set[str] = {
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_iam_policy",
        "aws_iam_user",
        "aws_iam_user_policy",
        "aws_iam_group",
        "aws_iam_group_policy",
        "aws_iam_policy_attachment",
        "aws_iam_instance_profile",
    }

    network_types_prefix = (
        "aws_vpc",
        "aws_subnet",
        "aws_security_group",
        "aws_security_group_rule",
        "aws_route_table",
        "aws_route",
        "aws_internet_gateway",
        "aws_nat_gateway",
        "aws_network_acl",
        "aws_lb",
        "aws_alb",
    )

    unencrypted_resource_types = {
        "aws_ebs_volume",
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_efs_file_system",
        "aws_elasticache_replication_group",
        "aws_elasticsearch_domain",
        "aws_opensearch_domain",
    }

    for rc in resource_changes:
        features["resource_change_count"] += 1

        rtype = rc.get("type", "")
        change = rc.get("change", {})
        actions = change.get("actions", [])
        after = get_after_values(change)

        if "create" in actions:
            features["create_count"] += 1
        if "update" in actions:
            features["update_count"] += 1
        if "delete" in actions:
            features["delete_count"] += 1

        if rtype in iam_types:
            features["iam_resource_count"] += 1

        if rtype.startswith(network_types_prefix):
            features["network_resource_count"] += 1

        if rtype == "aws_internet_gateway":
            features["internet_gateway_present"] = 1

        if rtype == "aws_nat_gateway":
            features["nat_gateway_present"] = 1

        if rtype == "aws_eks_cluster":
            print("DEBUG EKS after:")
            print(json.dumps(after, indent=2))
         # Case 1: direct field
            if after.get("endpoint_public_access") == True:
                features["eks_public_endpoint"] = 1

        # Case 2: nested inside vpc_config
            vpc_configs = safe_list(after.get("vpc_config"))

            for vpc_cfg in vpc_configs:
                if not isinstance(vpc_cfg, dict):
                    continue

        # detect public endpoint
                if vpc_cfg.get("endpoint_public_access") is True:
                    features["eks_public_endpoint"] = 1

        # detect open CIDR
            public_cidrs = safe_list(vpc_cfg.get("public_access_cidrs"))

            for cidr in public_cidrs:
                if is_public_cidr(cidr):
                    features["eks_public_cidr_open"] = 1
                    features["open_cidr_0_0_0_0"] = 1

        # optional direct public_access_cidrs check too
            public_cidrs_direct = safe_list(after.get("public_access_cidrs"))
            for cidr in public_cidrs_direct:
                if is_public_cidr(cidr):
                    features["eks_public_cidr_open"] = 1
                    features["open_cidr_0_0_0_0"] = 1

            enabled_logs = safe_list(after.get("enabled_cluster_log_types"))
            if not enabled_logs:
                features["logging_disabled"] = 1

        # Subnet checks
        if rtype == "aws_subnet":
            tags = after.get("tags", {}) or {}
            address = safe_str(rc.get("address"))

            is_public = False

        # Method 1: explicit subnet setting
            if after.get("map_public_ip_on_launch") is True:
                is_public = True

        # Method 2: module/resource naming
            if ".aws_subnet.public[" in address:
                is_public = True

        # Method 3: EKS public ELB tag
            if tags.get("kubernetes.io/role/elb") == "1":
                is_public = True

            if is_public:
                features["public_subnet_count"] += 1

        # Security group checks
        if rtype == "aws_security_group":
            ingress_rules = safe_list(after.get("ingress"))
            egress_rules = safe_list(after.get("egress"))

            features["security_group_rule_count"] += len(ingress_rules) + len(egress_rules)

            for rule in ingress_rules:
                cidr_blocks = safe_list(rule.get("cidr_blocks"))
                ipv6_cidr_blocks = safe_list(rule.get("ipv6_cidr_blocks"))

                if any(is_public_cidr(c) for c in cidr_blocks + ipv6_cidr_blocks):
                    features["open_cidr_0_0_0_0"] = 1

                features["sensitive_port_open_count"] += count_sensitive_ports(
                    rule.get("from_port"), rule.get("to_port")
                )

            for rule in egress_rules:
                cidr_blocks = safe_list(rule.get("cidr_blocks"))
                ipv6_cidr_blocks = safe_list(rule.get("ipv6_cidr_blocks"))

                if any(is_public_cidr(c) for c in cidr_blocks + ipv6_cidr_blocks):
                    features["public_egress_rule"] = 1

        if rtype == "aws_security_group_rule":
            features["security_group_rule_count"] += 1

            rule_type = safe_str(after.get("type")).lower()
            cidr_blocks = safe_list(after.get("cidr_blocks"))
            ipv6_cidr_blocks = safe_list(after.get("ipv6_cidr_blocks"))

            if rule_type == "egress" and any(is_public_cidr(c) for c in cidr_blocks + ipv6_cidr_blocks):
                features["public_egress_rule"] = 1

            if rule_type == "ingress":
                if any(is_public_cidr(c) for c in cidr_blocks + ipv6_cidr_blocks):
                    features["open_cidr_0_0_0_0"] = 1

                features["sensitive_port_open_count"] += count_sensitive_ports(
                    after.get("from_port"), after.get("to_port")
                )

        # Route checks
        if rtype == "aws_route":
            destination_cidr = safe_str(after.get("destination_cidr_block"))
            gateway_id = safe_str(after.get("gateway_id"))
            if destination_cidr == "0.0.0.0/0" and gateway_id:
                features["internet_gateway_present"] = 1

        # IAM wildcard checks
        if rtype in {
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
        }:
            policy_doc = after.get("policy")
            if isinstance(policy_doc, str):
                try:
                    policy_doc = json.loads(policy_doc)
                except json.JSONDecodeError:
                    policy_doc = None

            if isinstance(policy_doc, dict):
                statements = safe_list(policy_doc.get("Statement"))
                for stmt in statements:
                    actions_list = flatten_actions(stmt.get("Action"))
                    resources_list = flatten_resources(stmt.get("Resource"))

                    if "*" in actions_list:
                        features["iam_wildcard_action"] = 1
                    if "*" in resources_list:
                        features["iam_wildcard_resource"] = 1

        if rtype == "aws_iam_role":
            inline_policies = safe_list(after.get("inline_policy"))

            for pol in inline_policies:
                if not isinstance(pol, dict):
                    continue

                policy_doc = pol.get("policy")

                if isinstance(policy_doc, str):
                    try:
                        policy_doc = json.loads(policy_doc)
                    except json.JSONDecodeError:
                        continue

                if not isinstance(policy_doc, dict):
                    continue

                statements = safe_list(policy_doc.get("Statement"))

                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue

                    actions_list = flatten_actions(stmt.get("Action"))
                    resource_value = stmt.get("Resource")
                    resources_list = flatten_resources(resource_value)

                    if any("*" in str(a) for a in actions_list):
                        features["iam_wildcard_action"] = 1

                    if resource_value == "*" or resource_value == ["*"] or any(str(r).strip() == "*" for r in resources_list):
                        features["iam_wildcard_resource"] = 1
            

        # Encryption checks
        if rtype == "aws_ebs_volume":
            if after.get("encrypted") is False:
                features["unencrypted_resources"] += 1

        if rtype == "aws_db_instance":
            if after.get("storage_encrypted") is False:
                features["unencrypted_resources"] += 1

        if rtype == "aws_rds_cluster":
            if after.get("storage_encrypted") is False:
                features["unencrypted_resources"] += 1

        if rtype == "aws_efs_file_system":
            if not after.get("encrypted", False):
                features["unencrypted_resources"] += 1

        if rtype == "aws_s3_bucket_server_side_encryption_configuration":
            rules = safe_list(after.get("rule"))
            if not rules:
                features["unencrypted_resources"] += 1

        if rtype in {"aws_s3_bucket", "aws_s3_bucket_public_access_block"}:
            block_public_acls = after.get("block_public_acls")
            block_public_policy = after.get("block_public_policy")
            ignore_public_acls = after.get("ignore_public_acls")
            restrict_public_buckets = after.get("restrict_public_buckets")

            if all(v is True for v in [
                block_public_acls,
                block_public_policy,
                ignore_public_acls,
                restrict_public_buckets,
            ] if v is not None):
                features["s3_public_access_disabled"] = 1

        # Load balancer checks
        if rtype in {"aws_lb", "aws_alb"}:
            scheme = safe_str(after.get("internal")).lower()
            if scheme == "false" or after.get("internal") is False:
                features["load_balancer_public"] = 1

    return features


def append_to_csv(csv_path: str, row: Dict[str, int]) -> None:
    file_exists = os.path.isfile(csv_path)

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not file_exists or os.path.getsize(csv_path) == 0:
            writer.writeheader()
        writer.writerow(row)


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python extract_features.py <plan.json> <label> [output.csv]")
        sys.exit(1)

    plan_path = sys.argv[1]
    label = int(sys.argv[2])
    output_csv = sys.argv[3] if len(sys.argv) > 3 else "dataset.csv"

    features = extract_features(plan_path)
    features["label"] = label

    append_to_csv(output_csv, features)

    print(f"Features extracted and appended to {output_csv}")
    print(features)


if __name__ == "__main__":
    main()