"""
Self-evolving detection system with feedback loop for continuous learning.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import os
from pathlib import Path


@dataclass
class FeedbackEntry:
    """Represents a user feedback entry for model improvement."""
    id: str
    timestamp: datetime
    original_prediction: str
    corrected_label: str
    confidence: float
    url: str
    payload: str
    user_reason: Optional[str] = None
    feature_values: Optional[List[float]] = None
    context_factors: Optional[Dict[str, float]] = None


@dataclass
class FeedbackStats:
    """Statistics about feedback collection and model improvements."""
    total_feedbacks: int
    corrections_made: int
    accuracy_improvements: float
    false_positive_reductions: float
    last_retraining: Optional[datetime] = None
    pending_feedbacks: int = 0


class SelfEvolvingDetector:
    """
    Implements a feedback loop system that allows the model to learn from user corrections.
    """

    FEEDBACK_FILE = "feedback_data.json"
    MIN_FEEDBACK_FOR_RETRAINING = 10
    RETRAINING_INTERVAL_DAYS = 7

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.feedback_file = self.data_dir / self.FEEDBACK_FILE
        self.feedbacks: List[FeedbackEntry] = []
        self._load_feedbacks()

    def add_feedback(
        self,
        original_prediction: str,
        corrected_label: str,
        confidence: float,
        url: str,
        payload: str,
        user_reason: Optional[str] = None,
        feature_values: Optional[List[float]] = None,
        context_factors: Optional[Dict[str, float]] = None
    ) -> str:
        """
        Add user feedback for model improvement.

        Returns the feedback ID.
        """
        feedback_id = f"fb_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.feedbacks)}"

        feedback = FeedbackEntry(
            id=feedback_id,
            timestamp=datetime.now(),
            original_prediction=original_prediction,
            corrected_label=corrected_label,
            confidence=confidence,
            url=url,
            payload=payload,
            user_reason=user_reason,
            feature_values=feature_values,
            context_factors=context_factors
        )

        self.feedbacks.append(feedback)
        self._save_feedbacks()

        return feedback_id

    def should_retrain(self) -> bool:
        """
        Determine if the model should be retrained based on feedback volume and time.
        """
        if len(self.feedbacks) < self.MIN_FEEDBACK_FOR_RETRAINING:
            return False

        # Check if we have recent feedbacks that need processing
        recent_feedbacks = [
            f for f in self.feedbacks
            if (datetime.now() - f.timestamp).days < self.RETRAINING_INTERVAL_DAYS
        ]

        return len(recent_feedbacks) >= self.MIN_FEEDBACK_FOR_RETRAINING

    def get_training_data_from_feedback(self) -> Dict[str, Any]:
        """
        Extract training data from accumulated feedback for model retraining.
        """
        if not self.feedbacks:
            return {"features": [], "labels": []}

        # Convert feedback to training format
        features = []
        labels = []

        for feedback in self.feedbacks:
            if feedback.feature_values:
                features.append(feedback.feature_values)
                # Use corrected label, but weight by confidence
                label = 1 if feedback.corrected_label == "vulnerable" else 0
                labels.append(label)

        return {
            "features": features,
            "labels": labels,
            "metadata": {
                "total_feedbacks": len(self.feedbacks),
                "corrections": len([f for f in self.feedbacks if f.original_prediction != f.corrected_label]),
                "avg_confidence": sum(f.confidence for f in self.feedbacks) / len(self.feedbacks)
            }
        }

    def get_feedback_stats(self) -> FeedbackStats:
        """Get statistics about feedback collection."""
        total_feedbacks = len(self.feedbacks)
        corrections = len([
            f for f in self.feedbacks
            if f.original_prediction != f.corrected_label
        ])

        # Calculate accuracy improvement (simplified)
        accuracy_improvement = corrections / total_feedbacks if total_feedbacks > 0 else 0

        # Estimate false positive reduction
        false_positives_corrected = len([
            f for f in self.feedbacks
            if f.original_prediction == "vulnerable" and f.corrected_label == "safe"
        ])
        fp_reduction = false_positives_corrected / total_feedbacks if total_feedbacks > 0 else 0

        last_retraining = None
        if self.feedbacks:
            # In a real system, this would track actual retraining events
            last_retraining = max(f.timestamp for f in self.feedbacks)

        return FeedbackStats(
            total_feedbacks=total_feedbacks,
            corrections_made=corrections,
            accuracy_improvements=accuracy_improvement,
            false_positive_reductions=fp_reduction,
            last_retraining=last_retraining,
            pending_feedbacks=len([f for f in self.feedbacks if not hasattr(f, 'processed')])
        )

    def get_feedback_insights(self) -> Dict[str, Any]:
        """Generate insights from feedback data."""
        if not self.feedbacks:
            return {"insights": "No feedback data available yet."}

        insights = {
            "total_feedbacks": len(self.feedbacks),
            "correction_rate": len([f for f in self.feedbacks if f.original_prediction != f.corrected_label]) / len(self.feedbacks),
            "common_mistakes": self._analyze_common_mistakes(),
            "user_reasons": self._analyze_user_reasons(),
            "confidence_distribution": self._analyze_confidence_distribution()
        }

        return insights

    def _analyze_common_mistakes(self) -> Dict[str, int]:
        """Analyze patterns in model mistakes."""
        mistakes = {}

        for feedback in self.feedbacks:
            if feedback.original_prediction != feedback.corrected_label:
                key = f"{feedback.original_prediction}_to_{feedback.corrected_label}"
                mistakes[key] = mistakes.get(key, 0) + 1

        return dict(sorted(mistakes.items(), key=lambda x: x[1], reverse=True))

    def _analyze_user_reasons(self) -> Dict[str, int]:
        """Analyze user-provided reasons for corrections."""
        reasons = {}

        for feedback in self.feedbacks:
            if feedback.user_reason:
                # Simple categorization
                reason_lower = feedback.user_reason.lower()
                if "false positive" in reason_lower:
                    reasons["false_positive"] = reasons.get("false_positive", 0) + 1
                elif "legitimate" in reason_lower or "business" in reason_lower:
                    reasons["legitimate_business_logic"] = reasons.get("legitimate_business_logic", 0) + 1
                elif "test" in reason_lower or "development" in reason_lower:
                    reasons["development_testing"] = reasons.get("development_testing", 0) + 1
                else:
                    reasons["other"] = reasons.get("other", 0) + 1

        return reasons

    def _analyze_confidence_distribution(self) -> Dict[str, Any]:
        """Analyze confidence levels in feedback."""
        confidences = [f.confidence for f in self.feedbacks]

        if not confidences:
            return {"distribution": "No data"}

        return {
            "average": sum(confidences) / len(confidences),
            "high_confidence_corrections": len([c for c in confidences if c > 0.8]),
            "low_confidence_corrections": len([c for c in confidences if c < 0.5])
        }

    def _load_feedbacks(self):
        """Load feedback data from file."""
        if self.feedback_file.exists():
            try:
                with open(self.feedback_file, 'r') as f:
                    data = json.load(f)

                self.feedbacks = []
                for item in data.get('feedbacks', []):
                    # Convert timestamp string back to datetime
                    timestamp = datetime.fromisoformat(item['timestamp'])

                    feedback = FeedbackEntry(
                        id=item['id'],
                        timestamp=timestamp,
                        original_prediction=item['original_prediction'],
                        corrected_label=item['corrected_label'],
                        confidence=item['confidence'],
                        url=item['url'],
                        payload=item['payload'],
                        user_reason=item.get('user_reason'),
                        feature_values=item.get('feature_values'),
                        context_factors=item.get('context_factors')
                    )
                    self.feedbacks.append(feedback)

            except Exception as e:
                print(f"Error loading feedback data: {e}")
                self.feedbacks = []

    def _save_feedbacks(self):
        """Save feedback data to file."""
        try:
            data = {
                'feedbacks': [
                    {
                        'id': f.id,
                        'timestamp': f.timestamp.isoformat(),
                        'original_prediction': f.original_prediction,
                        'corrected_label': f.corrected_label,
                        'confidence': f.confidence,
                        'url': f.url,
                        'payload': f.payload,
                        'user_reason': f.user_reason,
                        'feature_values': f.feature_values,
                        'context_factors': f.context_factors
                    }
                    for f in self.feedbacks
                ]
            }

            with open(self.feedback_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error saving feedback data: {e}")

    def clear_old_feedbacks(self, days_to_keep: int = 90):
        """Clear feedback data older than specified days."""
        cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days_to_keep)

        original_count = len(self.feedbacks)
        self.feedbacks = [f for f in self.feedbacks if f.timestamp > cutoff_date]

        if len(self.feedbacks) < original_count:
            self._save_feedbacks()
            print(f"Cleared {original_count - len(self.feedbacks)} old feedback entries")