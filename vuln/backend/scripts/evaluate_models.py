
import pandas as pd
import joblib
from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix, precision_recall_curve, auc
import matplotlib.pyplot as plt
import numpy as np
import os
import logging

LGB_MODEL_PATH = "../artifacts/lightgbm_cve.joblib"
IF_MODEL_PATH = "../artifacts/isolation_forest_cve.joblib"
TEST_CSV = "../data/test.csv"
METRICS_PATH = "../artifacts/eval_metrics.json"


def evaluate_models():
    df = pd.read_csv(TEST_CSV)
    feature_cols = [col for col in df.columns if col not in ["id", "description", "published", "lastModified", "severity", "label"]]
    X = df[feature_cols]
    y = df["label"]

    # LightGBM/Ensemble
    lgb_model = joblib.load(LGB_MODEL_PATH)
    y_pred = lgb_model.predict_proba(X)[:,1] if hasattr(lgb_model, "predict_proba") else lgb_model.predict(X)
    metrics = {}
    if len(set(y)) < 2:
        print("Warning: Only one class present in y_true. ROC AUC score is not defined.")
        metrics["roc_auc"] = None
    else:
        roc_auc = roc_auc_score(y, y_pred)
        print(f"Ensemble ROC AUC: {roc_auc:.4f}")
        metrics["roc_auc"] = roc_auc
    y_pred_bin = (y_pred > 0.5).astype(int)
    print(classification_report(y, y_pred_bin))
    cm = confusion_matrix(y, y_pred_bin)
    print("Confusion Matrix:\n", cm)
    metrics["confusion_matrix"] = cm.tolist()
    # Precision-Recall curve
    if len(set(y)) > 1:
        precision, recall, _ = precision_recall_curve(y, y_pred)
        pr_auc = auc(recall, precision)
        print(f"PR AUC: {pr_auc:.4f}")
        metrics["pr_auc"] = pr_auc
        plt.figure()
        plt.plot(recall, precision, label="PR curve")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall Curve")
        plt.legend()
        pr_curve_path = os.path.join(os.path.dirname(METRICS_PATH), "pr_curve.png")
        plt.savefig(pr_curve_path)
        print(f"Saved PR curve to {pr_curve_path}")
    # Save metrics
    import json
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved evaluation metrics to {METRICS_PATH}")

    # Isolation Forest
    if_model = joblib.load(IF_MODEL_PATH)
    y_pred_if = if_model.predict(X)
    # Isolation Forest: -1 = anomaly, 1 = normal
    y_pred_if_bin = (y_pred_if == -1).astype(int)
    print("Isolation Forest classification report:")
    print(classification_report(y, y_pred_if_bin))
    cm_if = confusion_matrix(y, y_pred_if_bin)
    print("Isolation Forest Confusion Matrix:\n", cm_if)


if __name__ == "__main__":
    import argparse
    import os
    parser = argparse.ArgumentParser(description="Evaluate trained models on the test set.")
    default_data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    default_artifacts_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
    parser.add_argument("--test_csv", type=str, default=os.path.join(default_data_dir, "test.csv"), help="Test CSV file")
    parser.add_argument("--lgb_model", type=str, default=os.path.join(default_artifacts_dir, "lightgbm_cve.joblib"), help="LightGBM model path")
    parser.add_argument("--if_model", type=str, default=os.path.join(default_artifacts_dir, "isolation_forest_cve.joblib"), help="Isolation Forest model path")
    args = parser.parse_args()

    # Patch global variables for backward compatibility
    TEST_CSV = args.test_csv
    LGB_MODEL_PATH = args.lgb_model
    IF_MODEL_PATH = args.if_model
    evaluate_models()
