
import pandas as pd
import lightgbm as lgb
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
import joblib
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.model_selection import StratifiedKFold, cross_val_score
import numpy as np
import logging

TRAIN_CSV = "../data/train.csv"
LGB_MODEL_PATH = "../artifacts/lightgbm_cve.joblib"
IF_MODEL_PATH = "../artifacts/isolation_forest_cve.joblib"

def train_models(train_csv, lgb_model_path, if_model_path):
    df = pd.read_csv(train_csv)
    # Use only numeric features (including TF-IDF columns)
    exclude_cols = ["id", "description", "published", "lastModified", "severity", "cwe", "label"]
    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    feature_cols = [col for col in numeric_cols if col not in exclude_cols]
    X = df[feature_cols]
    y = df["label"]

    if X.shape[1] == 0:
        raise ValueError("No numeric features found for training. Please check preprocessing.")

    # Logging
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Training with {X.shape[0]} samples, {X.shape[1]} features.")

    # Handle class imbalance
    if len(y.unique()) > 1:
        sample_weight = compute_sample_weight(class_weight="balanced", y=y)
        logging.info(f"Class weights: {dict(zip(np.unique(y), compute_sample_weight(class_weight='balanced', y=y)))}")
    else:
        sample_weight = None

    # K-fold cross-validation and ensemble
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    lgbm = lgb.LGBMClassifier(objective="binary", n_estimators=100, class_weight="balanced", random_state=42)
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    ensemble = VotingClassifier(estimators=[('lgbm', lgbm), ('rf', rf)], voting='soft')
    if len(y.unique()) > 1:
        cv_scores = cross_val_score(ensemble, X, y, cv=skf, scoring='roc_auc')
        logging.info(f"Ensemble CV ROC AUC: {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")
        # Log train ROC AUC for overfitting detection
        ensemble.fit(X, y, sample_weight=sample_weight if sample_weight is not None else None)
        y_train_pred = ensemble.predict_proba(X)[:,1] if hasattr(ensemble, "predict_proba") else ensemble.predict(X)
        from sklearn.metrics import roc_auc_score
        train_auc = roc_auc_score(y, y_train_pred)
        logging.info(f"Ensemble Train ROC AUC: {train_auc:.4f}")
        joblib.dump(ensemble, lgb_model_path)
        print(f"Ensemble model (LightGBM+RF) saved to {lgb_model_path}")
        
        # SHAP explainability (for LightGBM part of ensemble)
        try:
            import shap
            import matplotlib.pyplot as plt
            explainer = None
            if hasattr(lgbm, 'booster_'):
                explainer = shap.TreeExplainer(lgbm.booster_)
            elif hasattr(lgbm, 'fit'):
                explainer = shap.Explainer(lgbm)
            if explainer is not None:
                shap_values = explainer.shap_values(X)
                shap.summary_plot(shap_values, X, show=False)
                shap_path = os.path.join(os.path.dirname(lgb_model_path), "shap_summary.png")
                plt.savefig(shap_path)
                print(f"Saved SHAP feature importance plot to {shap_path}")
        except Exception as e:
            print(f"SHAP explainability failed: {e}")
    else:
        print("Only one class present in training data. Skipping model training.")
        return

    # Isolation Forest (fit only on normal samples if available)
    if 0 in y.values:
        X_normal = X[y == 0]
        if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        if_model.fit(X_normal)
        joblib.dump(if_model, if_model_path)
        print(f"Isolation Forest model saved to {if_model_path}")
    else:
        print("Warning: No normal samples for Isolation Forest training.")


if __name__ == "__main__":
    import argparse
    import os
    parser = argparse.ArgumentParser(description="Train LightGBM and Isolation Forest models.")
    default_data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    default_artifacts_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
    parser.add_argument("--train_csv", type=str, default=os.path.join(default_data_dir, "train.csv"), help="Training CSV file")
    parser.add_argument("--lgb_model", type=str, default=os.path.join(default_artifacts_dir, "lightgbm_cve.joblib"), help="LightGBM model output path")
    parser.add_argument("--if_model", type=str, default=os.path.join(default_artifacts_dir, "isolation_forest_cve.joblib"), help="Isolation Forest model output path")
    args = parser.parse_args()
    train_models(args.train_csv, args.lgb_model, args.if_model)
