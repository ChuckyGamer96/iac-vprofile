import pandas as pd

df = pd.read_csv("dataset.csv")

def compute_score(row):
    score = 0

    # 🔴 Severe
    severe_flags = [
        row["eks_public_endpoint"],
        row["eks_public_cidr_open"],
        row["open_cidr_0_0_0_0"],
        row["logging_disabled"],
    ]

    # 🟡 Medium
    if row["public_egress_rule"] == 1:
        score += 1
    if row["sensitive_port_open_count"] >= 3:
        score += 2
    if row["unencrypted_resources"] > 0:
        score += 2

    # 🟢 Low
    if row["nat_gateway_present"] == 0:
        score += 1
    if row["public_subnet_count"] < 3:
        score += 1
    if row["s3_public_access_disabled"] == 0:
        score += 1

    return score, any(severe_flags)

# compute score + severe flag
results = df.apply(lambda row: compute_score(row), axis=1)
df["risk_score"] = results.apply(lambda x: x[0])
df["has_severe"] = results.apply(lambda x: x[1])

# FINAL LABEL LOGIC
df["label"] = df.apply(
    lambda row: 1 if (row["has_severe"] or row["risk_score"] >= 10) else 0,
    axis=1
)

df.to_csv("dataset_final.csv", index=False)

print("Done. Final labels generated.")