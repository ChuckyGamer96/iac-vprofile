#!/usr/bin/env python3

import sys
import json
import joblib
import pandas as pd

from extract_features import extract_features

DROP_COLS = [
    "open_cidr_0_0_0_0",
    "eks_public_cidr_open",
    "update_count",
    "delete_count",
    "internet_gateway_present",
    "iam_wildcard_action",
    "iam_wildcard_resource",
    "unencrypted_resources",
    "logging_disabled",
    "s3_public_access_disabled",
    "load_balancer_public",
]

def main():
    if len(sys.argv) < 3:
        print("Usage: python scripts/predict_risk.py <plan.json> <model.pkl>")
        sys.exit(1)

    plan_path = sys.argv[1]
    model_path = sys.argv[2]

    with open("models/training_features.json", "r", encoding="utf-8") as f:
        training_features = json.load(f)

    # Extract features from current Terraform plan
    features = extract_features(plan_path)

    # Drop same columns removed during training
    for col in DROP_COLS:
        features.pop(col, None)

    # Create DataFrame
    X = pd.DataFrame([features])

    # Ensure all training columns exist
    for col in training_features:
        if col not in X.columns:
            X[col] = 0

    # Match exact training order
    X = X[training_features]

    # Load trained model
    model = joblib.load(model_path)

    # Predict
    pred = int(model.predict(X)[0])

    risk_probability = None
    if hasattr(model, "predict_proba"):
        risk_probability = float(model.predict_proba(X)[0][1])

    print("\n=== ML Risk Prediction ===")
    print("Features used:")
    print(json.dumps(X.iloc[0].to_dict(), indent=2))

    print(f"\nPredicted label: {pred}")
    if risk_probability is not None:
        print(f"Risk probability: {risk_probability:.4f}")

    if pred == 1:
        print("ML_RESULT=RISKY")
        sys.exit(2)
    else:
        print("ML_RESULT=SAFE")
        sys.exit(0)

if __name__ == "__main__":
    main()