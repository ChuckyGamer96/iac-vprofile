import csv
import json
import os
import sys


def extract_features(plan):
    features = {
        "resource_change_count": 0,
        "create_count": 0,
        "update_count": 0,
        "delete_count": 0,
        "eks_public_endpoint": 0,
        "eks_public_cidr_open": 0,
        "public_egress_rule": 0,
        "security_group_rule_count": 0,
        "iam_resource_count": 0,
        "network_resource_count": 0
    }

    resource_changes = plan.get("resource_changes", [])
    features["resource_change_count"] = len(resource_changes)

    for rc in resource_changes:
        change = rc.get("change", {})
        actions = change.get("actions", [])
        resource_type = rc.get("type", "")
        after = change.get("after") or {}

        if "create" in actions:
            features["create_count"] += 1
        if "update" in actions:
            features["update_count"] += 1
        if "delete" in actions:
            features["delete_count"] += 1

        if resource_type == "aws_eks_cluster":
            vpc_config = after.get("vpc_config", [])
            for cfg in vpc_config:
                if cfg.get("endpoint_public_access") is True:
                    features["eks_public_endpoint"] = 1

                cidrs = cfg.get("public_access_cidrs", [])
                if "0.0.0.0/0" in cidrs:
                    features["eks_public_cidr_open"] = 1

        if resource_type == "aws_security_group_rule":
            features["security_group_rule_count"] += 1

            if after.get("type") == "egress":
                cidrs = after.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidrs:
                    features["public_egress_rule"] = 1

        if resource_type.startswith("aws_iam"):
            features["iam_resource_count"] += 1

        if (
            resource_type.startswith("aws_vpc")
            or resource_type.startswith("aws_subnet")
            or resource_type.startswith("aws_security_group")
        ):
            features["network_resource_count"] += 1

    return features


def append_to_csv(features, label, output_file="dataset.csv"):
    row = dict(features)
    row["label"] = label

    file_exists = os.path.isfile(output_file)
    fieldnames = list(row.keys())

    with open(output_file, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def main():
    if len(sys.argv) != 3:
        print("Usage: python extract_features.py <plan.json> <label>")
        print("Example: python extract_features.py plan.json 1")
        sys.exit(1)

    plan_file = sys.argv[1]

    try:
        label = int(sys.argv[2])
    except ValueError:
        print("Label must be 0 or 1")
        sys.exit(1)

    if label not in (0, 1):
        print("Label must be 0 or 1")
        sys.exit(1)

    with open(plan_file, "r") as f:
        plan = json.load(f)

    features = extract_features(plan)
    append_to_csv(features, label)

    print("Extracted Features:")
    for key, value in features.items():
        print(f"{key}: {value}")
    print(f"label: {label}")
    print("Saved to dataset.csv")


if __name__ == "__main__":
    main()