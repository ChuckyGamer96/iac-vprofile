import csv
import json
import os
import re
import sys


def load_plan(plan_path):
    with open(plan_path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_resource_changes(resource_changes):
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


def extract_plan_features(plan):
    resource_changes = plan.get("resource_changes", [])
    planned_values = plan.get("planned_values", {}).get("root_module", {})

    resource_change_count = len(resource_changes)
    create_count, update_count, delete_count = count_resource_changes(resource_changes)

    eks_public_endpoint = 0
    eks_public_cidr_open = 0
    public_egress_rule = 0
    security_group_rule_count = 0
    iam_resource_count = 0
    network_resource_count = 0

    def scan_module(module):
        nonlocal eks_public_endpoint
        nonlocal eks_public_cidr_open
        nonlocal public_egress_rule
        nonlocal security_group_rule_count
        nonlocal iam_resource_count
        nonlocal network_resource_count

        for r in module.get("resources", []):
            r_type = r.get("type", "")
            values = r.get("values", {})

            if r_type == "aws_eks_cluster":
                if values.get("endpoint_public_access") is True:
                    eks_public_endpoint = 1

                cidrs = values.get("public_access_cidrs", []) or []
                if "0.0.0.0/0" in cidrs:
                    eks_public_cidr_open = 1

            if r_type in [
                "aws_security_group",
                "aws_security_group_rule",
                "aws_vpc_security_group_egress_rule",
            ]:
                security_group_rule_count += 1

                egress = values.get("egress", [])
                if isinstance(egress, list):
                    for rule in egress:
                        cidrs = rule.get("cidr_blocks", []) or []
                        if "0.0.0.0/0" in cidrs:
                            public_egress_rule = 1

                cidrs = values.get("cidr_blocks", []) or []
                rule_type = values.get("type", "")
                if rule_type == "egress" and "0.0.0.0/0" in cidrs:
                    public_egress_rule = 1

            if r_type.startswith("aws_iam_"):
                iam_resource_count += 1

            if r_type.startswith("aws_vpc") or r_type.startswith("aws_subnet") or \
               r_type.startswith("aws_route") or r_type.startswith("aws_internet_gateway") or \
               r_type.startswith("aws_nat_gateway") or r_type.startswith("aws_eip"):
                network_resource_count += 1

        for child in module.get("child_modules", []):
            scan_module(child)

    scan_module(planned_values)

    return {
        "resource_change_count": resource_change_count,
        "create_count": create_count,
        "update_count": update_count,
        "delete_count": delete_count,
        "eks_public_endpoint": eks_public_endpoint,
        "eks_public_cidr_open": eks_public_cidr_open,
        "public_egress_rule": public_egress_rule,
        "security_group_rule_count": security_group_rule_count,
        "iam_resource_count": iam_resource_count,
        "network_resource_count": network_resource_count,
    }


def parse_tfsec(tfsec_path):
    with open(tfsec_path, "r", encoding="utf-8") as f:
        text = f.read()

    passed = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    m = re.search(r"passed\s+(\d+)", text, re.IGNORECASE)
    if m:
        passed = int(m.group(1))

    m = re.search(r"critical\s+(\d+)", text, re.IGNORECASE)
    if m:
        critical = int(m.group(1))

    m = re.search(r"high\s+(\d+)", text, re.IGNORECASE)
    if m:
        high = int(m.group(1))

    m = re.search(r"medium\s+(\d+)", text, re.IGNORECASE)
    if m:
        medium = int(m.group(1))

    m = re.search(r"low\s+(\d+)", text, re.IGNORECASE)
    if m:
        low = int(m.group(1))

    tfsec_total = critical + high + medium + low

    return {
        "tfsec_passed": passed,
        "tfsec_critical": critical,
        "tfsec_high": high,
        "tfsec_medium": medium,
        "tfsec_low": low,
        "tfsec_total": tfsec_total,
    }


def append_to_csv(output_path, row):
    file_exists = os.path.exists(output_path)

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
        "tfsec_passed",
        "tfsec_critical",
        "tfsec_high",
        "tfsec_medium",
        "tfsec_low",
        "tfsec_total",
        "label",
    ]

    with open(output_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def main():
    if len(sys.argv) != 4:
        print("Usage: python extract_features_v2.py <plan.json> <tfsec.txt> <label>")
        sys.exit(1)

    plan_path = sys.argv[1]
    tfsec_path = sys.argv[2]
    label = int(sys.argv[3])

    plan = load_plan(plan_path)
    plan_features = extract_plan_features(plan)
    tfsec_features = parse_tfsec(tfsec_path)

    row = {**plan_features, **tfsec_features, "label": label}

    print("Extracted Features:")
    for k, v in row.items():
        print(f"{k}: {v}")

    append_to_csv("dataset_v2.csv", row)
    print("Saved to dataset_v2.csv")


if __name__ == "__main__":
    main()