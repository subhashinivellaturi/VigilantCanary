from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Iterable, List, Sequence

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Suppress LightGBM warnings
warnings.filterwarnings("ignore", category=UserWarning, module="lightgbm")


@dataclass
class PredictionResult:
    label: str
    probability: float
    anomaly_score: float
    feature_insights: List[dict]


class VulnerabilityPipeline:
    def __init__(self, random_state: int = 42) -> None:
        self.scaler = StandardScaler()
        self.kmeans = KMeans(n_clusters=2, random_state=random_state)  # Added clustering
        self.isolation_forests = [IsolationForest(contamination=0.12, random_state=random_state) for _ in range(2)]
        self.classifier = LGBMClassifier(
            n_estimators=250,
            max_depth=-1,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.9,
            random_state=random_state,
        )
        self.feature_names: List[str] = []
        self.report: dict | None = None

    def fit(self, features: np.ndarray, labels: Sequence[int], feature_names: Iterable[str]) -> None:
        self.feature_names = list(feature_names)
        scaled = self.scaler.fit_transform(features)
        clusters = self.kmeans.fit_predict(scaled)
        
        # Fit separate Isolation Forest for each cluster
        anomaly_scores = np.zeros((scaled.shape[0], 1))
        for cluster_id in range(2):
            mask = clusters == cluster_id
            if np.sum(mask) > 0:
                cluster_data = scaled[mask]
                self.isolation_forests[cluster_id].fit(cluster_data)
                scores = -self.isolation_forests[cluster_id].decision_function(cluster_data)
                anomaly_scores[mask] = scores.reshape(-1, 1)
        
        augmented = np.hstack([scaled, anomaly_scores])
        self.classifier.fit(augmented, labels)

        _, X_eval, _, y_eval = train_test_split(augmented, labels, test_size=0.2, random_state=42, stratify=labels)
        preds = self.classifier.predict(X_eval)
        report = classification_report(y_eval, preds, output_dict=True, zero_division=0)
        self.report = report

    def predict(self, features: np.ndarray) -> PredictionResult:
        # Defensive checks: ensure inputs and model outputs are well-formed
        if features is None or getattr(features, "shape", (0,))[0] == 0:
            # No features provided -> return safe default prediction
            return PredictionResult(label="safe", probability=0.0, anomaly_score=0.0, feature_insights=[])

        scaled = self.scaler.transform(features)
        if scaled is None or getattr(scaled, "shape", (0,))[0] == 0:
            return PredictionResult(label="safe", probability=0.0, anomaly_score=0.0, feature_insights=[])

        clusters = self.kmeans.predict(scaled)
        anomaly_scores = np.zeros(scaled.shape[0])
        for i, cluster_id in enumerate(clusters):
            anomaly_scores[i] = -self.isolation_forests[cluster_id].decision_function(scaled[i:i+1])[0]

        augmented = np.hstack([scaled, anomaly_scores.reshape(-1, 1)])

        proba = None
        try:
            proba = self.classifier.predict_proba(augmented)
        except Exception:
            proba = None

        # Default safe probability if model outputs are missing/unexpected
        probability = 0.0
        if proba is not None and len(proba) > 0:
            row = proba[0]
            if getattr(row, "__len__", None) and len(row) >= 2:
                try:
                    probability = float(row[1])
                except Exception:
                    probability = 0.0

        label = "vulnerable" if probability >= 0.5 else "safe"

        first_scaled = scaled[0] if getattr(scaled, "shape", (0,))[0] > 0 else np.zeros(len(self.feature_names) or 1)
        insights = self._rank_features(first_scaled)

        anomaly_val = float(anomaly_scores[0]) if len(anomaly_scores) > 0 else 0.0
        return PredictionResult(label=label, probability=probability, anomaly_score=anomaly_val, feature_insights=insights)

    def _rank_features(self, scaled_features: np.ndarray) -> List[dict]:
        feature_weights = np.abs(scaled_features)
        rankings = np.argsort(feature_weights)[::-1]
        insights = []
        for idx in rankings[:5]:
            insights.append(
                {
                    "feature": self.feature_names[idx],
                    "contribution": float(feature_weights[idx]),
                }
            )
        return insights

    def update_model(self, new_features: np.ndarray, new_labels: Sequence[int]) -> None:
        """
        Incrementally update the model with new data for real-time learning.
        This addresses the limitation of static models by allowing continuous adaptation.
        """
        if not hasattr(self, 'classifier') or self.classifier is None:
            raise ValueError("Model must be fitted before updating")
        
        # Scale new features
        scaled_new = self.scaler.transform(new_features)
        
        # Get clusters for new data
        clusters = self.kmeans.predict(scaled_new)
        anomaly_scores = np.zeros((scaled_new.shape[0], 1))
        for cluster_id in range(2):
            mask = clusters == cluster_id
            if np.sum(mask) > 0:
                cluster_data = scaled_new[mask]
                scores = -self.isolation_forests[cluster_id].decision_function(cluster_data)
                anomaly_scores[mask] = scores.reshape(-1, 1)
        
        augmented_new = np.hstack([scaled_new, anomaly_scores])
        
        # Update LightGBM model incrementally
        self.classifier = LGBMClassifier(
            n_estimators=self.classifier.n_estimators + 50,  # Add more estimators
            max_depth=self.classifier.max_depth,
            learning_rate=self.classifier.learning_rate,
            subsample=self.classifier.subsample,
            colsample_bytree=self.classifier.colsample_bytree,
            random_state=self.classifier.random_state,
            init_model=self.classifier,  # Use current model as init
        )
        
        # Retrain with combined data (simplified - in practice, you'd keep historical data)
        # For demonstration, we'll refit with new data only
        self.classifier.fit(augmented_new, new_labels)

    def summary(self) -> dict:
        """Return a summary of the model performance metrics."""
        if self.report is None:
            return {"metrics": {}}
        
        # Extract key metrics from the classification report
        metrics = {}
        if "weighted avg" in self.report:
            weighted_avg = self.report["weighted avg"]
            metrics.update({
                "precision": weighted_avg.get("precision", 0.0),
                "recall": weighted_avg.get("recall", 0.0),
                "f1_score": weighted_avg.get("f1-score", 0.0),
                "accuracy": self.report.get("accuracy", 0.0),
            })
        
        # Add macro averages if available
        if "macro avg" in self.report:
            macro_avg = self.report["macro avg"]
            metrics.update({
                "macro_precision": macro_avg.get("precision", 0.0),
                "macro_recall": macro_avg.get("recall", 0.0),
                "macro_f1_score": macro_avg.get("f1-score", 0.0),
            })
        
        return {"metrics": metrics}
