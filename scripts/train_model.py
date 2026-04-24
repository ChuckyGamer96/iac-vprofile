#!/usr/bin/env python3

import os
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ----------------------------
# 1. Load dataset
# ----------------------------
DATASET_PATH = "dataset.csv"

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

df = pd.read_csv(DATASET_PATH)

print("\n=== Dataset Preview ===")
print(df.head())

print("\n=== Dataset Shape ===")
print(df.shape)

print("\n=== Column Names ===")
print(df.columns.tolist())

# ----------------------------
# 2. Basic cleaning
# ----------------------------
df = df.dropna(how="all")
df = df.drop_duplicates()

if "label" not in df.columns:
    raise ValueError("The dataset must contain a 'label' column.")

bool_map = {
    "true": 1, "false": 0,
    "True": 1, "False": 0,
    True: 1, False: 0
}
df = df.replace(bool_map)

for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors="ignore")

# ----------------------------
# 3. Separate features/target
# ----------------------------
final_features = [
    "eks_public_endpoint",
    "eks_public_cidr_open",
    "public_egress_rule",
    "open_cidr_0_0_0_0",
    "sensitive_port_open_count",
    "nat_gateway_present",
    "public_subnet_count",
    "unencrypted_resources",
    "logging_disabled",
    "s3_public_access_disabled",
    "load_balancer_public",
]

missing_features = [col for col in final_features if col not in df.columns]
if missing_features:
    raise ValueError(f"Missing required feature columns: {missing_features}")

X = df[final_features]
y = df["label"]

print("\n=== Final Features Used ===")
print(X.columns.tolist())

print("\n=== Label Distribution ===")
print(y.value_counts())

# Save final training feature list for inference
os.makedirs("models", exist_ok=True)
with open("models/training_features.json", "w", encoding="utf-8") as f:
    json.dump(X.columns.tolist(), f, indent=2)

# ----------------------------
# 4. Train/test split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\n=== Train/Test Split ===")
print(f"Train size: {X_train.shape[0]}")
print(f"Test size : {X_test.shape[0]}")

# ----------------------------
# 5. Build models
# ----------------------------
logreg_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler()),
    ("model", LogisticRegression(random_state=42, max_iter=1000))
])

rf_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("model", RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    ))
])

models = {
    "Logistic Regression": logreg_pipeline,
    "Random Forest": rf_pipeline
}

# ----------------------------
# 6. Train + evaluate
# ----------------------------
os.makedirs("results", exist_ok=True)

results = []

for model_name, pipeline in models.items():
    print(f"\n{'='*50}")
    print(f"Training: {model_name}")
    print(f"{'='*50}")

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(
        pipeline, X, y,
        cv=cv,
        scoring="f1"
    )

    print("\n5-Fold CV F1 Scores:")
    print(cv_scores)
    print(f"Mean CV F1: {cv_scores.mean():.4f}")

    results.append({
        "model": model_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "cv_f1_mean": cv_scores.mean()
    })

    safe_name = model_name.lower().replace(" ", "_")
    model_path = f"models/{safe_name}.pkl"
    joblib.dump(pipeline, model_path)
    print(f"\nSaved model to: {model_path}")

# ----------------------------
# 7. Save summary results
# ----------------------------
results_df = pd.DataFrame(results)
results_df.to_csv("results/model_results.csv", index=False)

print("\n=== Final Model Comparison ===")
print(results_df)

print("\nSaved comparison results to results/model_results.csv")