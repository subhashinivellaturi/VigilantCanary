"""
Explainable AI service using SHAP for vulnerability detection explanations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import numpy as np


@dataclass
class SHAPExplanation:
    """SHAP-based explanation for a prediction."""
    base_value: float
    prediction_value: float
    feature_importance: List[Dict[str, Any]]
    waterfall_explanation: str
    top_contributing_features: List[str]


class ExplainableAIService:
    """
    Provides explainable AI explanations using SHAP (SHapley Additive exPlanations).
    """

    @staticmethod
    def explain_prediction(
        model: Any,
        feature_values: np.ndarray,
        feature_names: List[str],
        prediction_label: str
    ) -> SHAPExplanation:
        """
        Generate SHAP explanation for a model prediction.

        Args:
            model: Trained ML model (LightGBM, etc.)
            feature_values: Feature vector for the prediction
            feature_names: Names of the features
            prediction_label: The predicted label

        Returns:
            SHAPExplanation with detailed breakdown
        """
        try:
            import shap
        except ImportError:
            # Fallback explanation if SHAP is not available
            return SHAPExplanation(
                base_value=0.5,
                prediction_value=0.5,
                feature_importance=[],
                waterfall_explanation="SHAP library not available. Using simplified explanation.",
                top_contributing_features=[]
            )

        try:
            # Create explainer (using TreeExplainer for tree-based models like LightGBM)
            explainer = shap.TreeExplainer(model)

            # Calculate SHAP values
            shap_values = explainer.shap_values(feature_values)

            # Handle multi-class case
            if isinstance(shap_values, list) and len(shap_values) > 1:
                # For binary classification, use the positive class values
                shap_vals = shap_values[1] if len(shap_values) == 2 else shap_values[0]
            else:
                shap_vals = shap_values

            # Get the SHAP values for this instance
            instance_shap = shap_vals[0] if len(shap_vals.shape) > 1 else shap_vals

            # Calculate base value and prediction
            base_value = explainer.expected_value
            if isinstance(base_value, (list, np.ndarray)):
                base_value = base_value[1] if len(base_value) == 2 else base_value[0]

            prediction_value = float(base_value + np.sum(instance_shap))

            # Create feature importance list
            feature_importance = []
            for i, (name, value, shap_val) in enumerate(zip(feature_names, feature_values[0], instance_shap)):
                feature_importance.append({
                    "name": name,
                    "original_value": float(value),
                    "shap_value": float(shap_val),
                    "contribution": float(shap_val),
                    "direction": "increases" if shap_val > 0 else "decreases"
                })

            # Sort by absolute SHAP value
            feature_importance.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

            # Generate waterfall explanation
            waterfall_explanation = ExplainableAIService._generate_waterfall_explanation(
                base_value, prediction_value, feature_importance[:5]  # Top 5 features
            )

            # Get top contributing features
            top_contributing_features = [f["name"] for f in feature_importance[:3]]

            return SHAPExplanation(
                base_value=float(base_value),
                prediction_value=prediction_value,
                feature_importance=feature_importance,
                waterfall_explanation=waterfall_explanation,
                top_contributing_features=top_contributing_features
            )

        except Exception as e:
            # Fallback for any SHAP calculation errors
            return SHAPExplanation(
                base_value=0.5,
                prediction_value=0.5,
                feature_importance=[],
                waterfall_explanation=f"SHAP calculation failed: {str(e)}. Using simplified explanation.",
                top_contributing_features=[]
            )

    @staticmethod
    def _generate_waterfall_explanation(
        base_value: float,
        final_prediction: float,
        top_features: List[Dict[str, Any]]
    ) -> str:
        """Generate a human-readable waterfall explanation."""
        explanation_parts = []

        explanation_parts.append(f"Base prediction: {base_value:.3f}")
        current_value = base_value

        for feature in top_features:
            contribution = feature["shap_value"]
            direction = "pushes toward" if contribution > 0 else "pushes away from"
            label = "vulnerable" if contribution > 0 else "safe"

            explanation_parts.append(f"Feature '{feature['name']}' {direction} {label} prediction by {abs(contribution):.3f}")
            current_value += contribution

        explanation_parts.append(f"Final prediction: {current_value:.3f}")
        return " ".join(explanation_parts)

    @staticmethod
    def get_feature_descriptions() -> Dict[str, str]:
        """Get human-readable descriptions for features."""
        return {
            "url_length": "Length of the URL (longer URLs may indicate obfuscation)",
            "payload_length": "Length of the request payload",
            "special_chars_ratio": "Ratio of special characters in the payload",
            "sql_keywords": "Number of SQL keywords detected",
            "xss_patterns": "Number of XSS attack patterns found",
            "path_traversal_attempts": "Number of path traversal indicators",
            "entropy": "Shannon entropy of the payload (measures randomness)",
            "script_tags": "Number of script tags in the payload",
            "union_select": "Presence of UNION SELECT pattern",
            "comment_patterns": "SQL comment patterns (/* */, --, #)",
            "error_based_payloads": "Payloads designed to trigger database errors",
            "time_based_payloads": "Time-delay based SQL injection attempts",
            "anomaly_score": "Statistical anomaly score from Isolation Forest"
        }

    @staticmethod
    def explain_feature_contribution(feature_name: str, contribution: float) -> str:
        """Provide detailed explanation for a specific feature's contribution."""
        descriptions = ExplainableAIService.get_feature_descriptions()

        base_desc = descriptions.get(feature_name, f"Feature: {feature_name}")

        if contribution > 0:
            return f"{base_desc} - This evidence increases the likelihood of a vulnerability."
        else:
            return f"{base_desc} - This evidence suggests the request is more likely safe."

    @staticmethod
    def generate_counterfactual_explanation(
        original_features: Dict[str, float],
        shap_values: Dict[str, float],
        prediction: str
    ) -> str:
        """
        Generate counterfactual explanations: "What would need to change for this to be safe?"
        """
        if prediction == "safe":
            return "This request appears safe. No significant changes needed for safety."

        # Find features that most contribute to vulnerability
        sorted_features = sorted(shap_values.items(), key=lambda x: x[1], reverse=True)

        counterfactuals = []
        for feature_name, shap_val in sorted_features[:3]:  # Top 3 contributors
            if shap_val > 0.1:  # Significant contribution
                if "sql" in feature_name.lower():
                    counterfactuals.append("remove SQL keywords like UNION, SELECT, DROP")
                elif "xss" in feature_name.lower() or "script" in feature_name.lower():
                    counterfactuals.append("remove script tags and JavaScript code")
                elif "path" in feature_name.lower():
                    counterfactuals.append("avoid directory traversal patterns like ../")
                elif "special_chars" in feature_name.lower():
                    counterfactuals.append("reduce special character usage")
                else:
                    counterfactuals.append(f"reduce {feature_name.replace('_', ' ')}")

        if counterfactuals:
            return f"To make this request safe, consider: {'; '.join(counterfactuals)}."
        else:
            return "Multiple factors contribute to this classification. Manual security review recommended."