import csv
import json
import os
import re
import sys
from typing import Any


def load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_resource_changes(resource_changes: list[dict[str, Any]]) -> tuple[int, int, int]:
    create_count = 0
    update_count = 0
    delete_count = 0

    for rc in resource_changes:
        actions = rc.get("change", {}).get("actions", [])
        if "create" in actions:
            create_count += 1
        if "update" in actions:
            update_count += 1
        if "delete" in actions:
            delete_count += 1

    return create_count, update_count, delete_count


def extract_plan_features(plan: dict[str, Any]) -> dict[str, int]:
    resource_changes = plan.get("resource_changes", [])
    root_module = plan.get("planned_values", {}).get("root_module", {})

    resource_change_count = len(resource_changes)
    create_count, update_count, delete_count = count_resource_changes(resource_changes)

    features = {
        "resource_change_count": resource_change_count,
        "create_count": create_count,
        "update_count": update_count,
        "delete_count": delete_count,
        "eks_public_endpoint": 0,
        "eks_public_cidr_open": 0,
        "public_egress_rule": 0,
        "security_group_rule_count": 0,
        "iam_resource_count": 0,
        "network_resource_count": 0,
        "vpc_flow_logs_enabled": 0,
        "eks_logging_enabled": 0,
        "node_group_count": 0,
        "total_desired_nodes": 0,
        "instance_diversity": 0,
    }

    instance_types_seen: set[str] = set()

    def scan_module(module: dict[str, Any]) -> None:
        for resource in module.get("resources", []):
            r_type = resource.get("type", "")
            values = resource.get("values", {}) or {}

            # -----------------------------
            # EKS cluster security features
            # -----------------------------
            if r_type == "aws_eks_cluster":
                if values.get("endpoint_public_access") is True:
                    features["eks_public_endpoint"] = 1

                public_cidrs = values.get("public_access_cidrs", []) or []
                if "0.0.0.0/0" in public_cidrs:
                    features["eks_public_cidr_open"] = 1

                enabled_logs = values.get("enabled_cluster_log_types", []) or []
                if isinstance(enabled_logs, list) and len(enabled_logs) > 0:
                    features["eks_logging_enabled"] = 1

            # -----------------------------
            # Security groups / egress
            # -----------------------------
            if r_type in {
                "aws_security_group",
                "aws_security_group_rule",
                "aws_vpc_security_group_egress_rule",
                "aws_vpc_security_group_ingress_rule",
            }:
                features["security_group_rule_count"] += 1

            if r_type == "aws_security_group":
                egress_rules = values.get("egress", []) or []
                for rule in egress_rules:
                    cidrs = rule.get("cidr_blocks", []) or []
                    ipv6_cidrs = rule.get("ipv6_cidr_blocks", []) or []
                    if "0.0.0.0/0" in cidrs or "::/0" in ipv6_cidrs:
                        features["public_egress_rule"] = 1

            if r_type in {"aws_security_group_rule", "aws_vpc_security_group_egress_rule"}:
                rule_type = values.get("type", "")
                cidrs = values.get("cidr_blocks", []) or []
                ipv6_cidrs = values.get("ipv6_cidr_blocks", []) or []

                is_egress_resource = (
                    r_type == "aws_vpc_security_group_egress_rule"
                    or rule_type == "egress"
                )

                if is_egress_resource and (
                    "0.0.0.0/0" in cidrs or "::/0" in ipv6_cidrs
                ):
                    features["public_egress_rule"] = 1

            # -----------------------------
            # IAM count
            # -----------------------------
            if r_type.startswith("aws_iam_"):
                features["iam_resource_count"] += 1

            # -----------------------------
            # Network count
            # -----------------------------
            network_prefixes = (
                "aws_vpc",
                "aws_subnet",
                "aws_route",
                "aws_route_table",
                "aws_route_table_association",
                "aws_internet_gateway",
                "aws_nat_gateway",
                "aws_eip",
                "aws_network_acl",
                "aws_network_interface",
            )
            if r_type.startswith(network_prefixes):
                features["network_resource_count"] += 1

            # -----------------------------
            # VPC Flow Logs
            # -----------------------------
            if r_type == "aws_flow_log":
                features["vpc_flow_logs_enabled"] = 1

            # -----------------------------
            # Managed node groups
            # -----------------------------
            if r_type == "aws_eks_node_group":
                features["node_group_count"] += 1

                scaling = values.get("scaling_config", [])
                if isinstance(scaling, list) and len(scaling) > 0:
                    desired = scaling[0].get("desired_size")
                    if isinstance(desired, int):
                        features["total_desired_nodes"] += desired

                instance_types = values.get("instance_types", []) or []
                if isinstance(instance_types, list):
                    for inst in instance_types:
                        if isinstance(inst, str) and inst.strip():
                            instance_types_seen.add(inst.strip())

        for child in module.get("child_modules", []):
            scan_module(child)

    scan_module(root_module)

    if len(instance_types_seen) > 1:
        features["instance_diversity"] = 1

    return features


def parse_tfsec(tfsec_path: str) -> dict[str, int]:
    with open(tfsec_path, "r", encoding="utf-8") as f:
        text = f.read()

    def extract_count(label: str) -> int:
        match = re.search(rf"{label}\s+(\d+)", text, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    critical = extract_count("critical")
    high = extract_count("high")
    medium = extract_count("medium")
    low = extract_count("low")
    passed = extract_count("passed")

    return {
        "tfsec_passed": passed,
        "tfsec_critical": critical,
        "tfsec_high": high,
        "tfsec_medium": medium,
        "tfsec_low": low,
        "tfsec_total": critical + high + medium + low,
    }


def append_to_csv(output_path: str, row: dict[str, int]) -> None:
    fieldnames = [
        "resource_change_count",
        "create_count",
        "update_count",
        "delete_count",
        "eks_public_endpoint",
        "eks_public_cidr_open",
        "public_egress_rule",
        "security_group_rule_count",
        "iam_resource_count",
        "network_resource_count",
        "vpc_flow_logs_enabled",
        "eks_logging_enabled",
        "node_group_count",
        "total_desired_nodes",
        "instance_diversity",
        "tfsec_passed",
        "tfsec_critical",
        "tfsec_high",
        "tfsec_medium",
        "tfsec_low",
        "tfsec_total",
        "label",
    ]

    file_exists = os.path.exists(output_path)

    with open(output_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def main() -> None:
    if len(sys.argv) != 4:
        print("Usage: python scripts/extract_features_v2.py <plan.json> <tfsec.txt> <label>")
        sys.exit(1)

    plan_path = sys.argv[1]
    tfsec_path = sys.argv[2]

    try:
        label = int(sys.argv[3])
    except ValueError:
        print("Error: label must be 0 or 1")
        sys.exit(1)

    if label not in (0, 1):
        print("Error: label must be 0 or 1")
        sys.exit(1)

    plan = load_json(plan_path)
    plan_features = extract_plan_features(plan)
    tfsec_features = parse_tfsec(tfsec_path)

    row = {
        **plan_features,
        **tfsec_features,
        "label": label,
    }

    print("Extracted features:")
    for key, value in row.items():
        print(f"{key}: {value}")

    append_to_csv("dataset_v2.csv", row)
    print("\nSaved row to dataset_v2.csv")


if __name__ == "__main__":
    main()