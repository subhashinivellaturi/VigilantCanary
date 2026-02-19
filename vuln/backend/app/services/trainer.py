from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

import pandas as pd

from .pipeline import VulnerabilityPipeline

SAFE_SEEDS = [
    {
        "url_length": 42,
        "payload_length": 28,
        "num_params": 2,
        "suspicious_token_count": 0,
        "script_tag_count": 0,
        "sql_keyword_count": 0,
        "sensitive_file_hits": 0,
        "js_event_count": 0,
        "entropy": 2.6,
        "uppercase_ratio": 0.05,
        "numeric_density": 0.12,
        "label": 0,
    },
    {
        "url_length": 65,
        "payload_length": 10,
        "num_params": 1,
        "suspicious_token_count": 0,
        "script_tag_count": 0,
        "sql_keyword_count": 0,
        "sensitive_file_hits": 0,
        "js_event_count": 0,
        "entropy": 1.8,
        "uppercase_ratio": 0.02,
        "numeric_density": 0.05,
        "label": 0,
    },
    {
        "url_length": 88,
        "payload_length": 12,
        "num_params": 3,
        "suspicious_token_count": 1,
        "script_tag_count": 0,
        "sql_keyword_count": 0,
        "sensitive_file_hits": 0,
        "js_event_count": 1,
        "entropy": 2.2,
        "uppercase_ratio": 0.03,
        "numeric_density": 0.09,
        "label": 0,
    },
]

VULNERABLE_SEEDS = [
    {
        "url_length": 120,
        "payload_length": 240,
        "num_params": 6,
        "suspicious_token_count": 3,
        "script_tag_count": 2,
        "sql_keyword_count": 2,
        "sensitive_file_hits": 1,
        "js_event_count": 2,
        "entropy": 4.2,
        "uppercase_ratio": 0.18,
        "numeric_density": 0.32,
        "label": 1,
    },
    {
        "url_length": 96,
        "payload_length": 180,
        "num_params": 5,
        "suspicious_token_count": 4,
        "script_tag_count": 1,
        "sql_keyword_count": 3,
        "sensitive_file_hits": 2,
        "js_event_count": 3,
        "entropy": 4.9,
        "uppercase_ratio": 0.22,
        "numeric_density": 0.41,
        "label": 1,
    },
    {
        "url_length": 140,
        "payload_length": 80,
        "num_params": 7,
        "suspicious_token_count": 2,
        "script_tag_count": 1,
        "sql_keyword_count": 4,
        "sensitive_file_hits": 1,
        "js_event_count": 1,
        "entropy": 3.6,
        "uppercase_ratio": 0.11,
        "numeric_density": 0.28,
        "label": 1,
    },
]


@dataclass
class TrainingArtifact:
    pipeline: VulnerabilityPipeline
    dataset_size: int


class VulnerabilityTrainer:
    def __init__(
        self,
        target_dataset_size: int = 5000,
        noise: float = 0.18,
        dataset_path: str | Path | None = None,
        use_synthetic: bool = False,
        synthetic_ratio: float = 0.5,
    ) -> None:
        self.target_dataset_size = target_dataset_size
        self.noise = noise
        self.feature_names = [
            "url_length",
            "payload_length",
            "num_params",
            "suspicious_token_count",
            "script_tag_count",
            "sql_keyword_count",
            "sensitive_file_hits",
            "js_event_count",
            "entropy",
            "uppercase_ratio",
            "numeric_density",
        ]
        default_data_dir = Path(__file__).resolve().parents[2] / "data"
        default_dataset = default_data_dir / "dataset_5k.csv"
        self.dataset_path = Path(dataset_path) if dataset_path else default_dataset
        self.use_synthetic = use_synthetic
        self.synthetic_ratio = synthetic_ratio

    def build_dataset(self) -> pd.DataFrame:
        if self.dataset_path.exists():
            df = pd.read_csv(self.dataset_path)
            missing = set(self.feature_names + ["label"]) - set(df.columns)
            if missing:
                raise ValueError(f"Dataset at {self.dataset_path} missing columns: {missing}")
            return df[self.feature_names + ["label"]]
        return self._build_synthetic_dataset()

    def _build_synthetic_dataset(self) -> pd.DataFrame:
        half = self.target_dataset_size // 2
        rows: List[dict] = []
        rows.extend(self._generate_samples(SAFE_SEEDS, half))
        rows.extend(self._generate_samples(VULNERABLE_SEEDS, half))

        while len(rows) < self.target_dataset_size:
            rows.append(self._generate_samples(VULNERABLE_SEEDS, 1)[0])

        df = pd.DataFrame(rows[: self.target_dataset_size])
        return df[self.feature_names + ["label"]]

    def _generate_samples(self, seeds: List[dict], desired: int) -> List[dict]:
        samples: List[dict] = []
        if desired <= 0:
            return samples
        for idx in range(desired):
            seed = seeds[idx % len(seeds)]
            noisy_row = {
                key: self._inject_noise(seed[key]) if key != "label" else seed[key]
                for key in seed
            }
            samples.append(noisy_row)
        return samples

    def _inject_noise(self, value: float) -> float:
        jitter = random.uniform(-self.noise, self.noise)
        adjusted = value + (value * jitter)
        return max(adjusted, 0.0)

    def train(self) -> TrainingArtifact:
        dataset = self.build_dataset()

        # Optionally augment with synthetic/adversarial data
        if self.use_synthetic:
            try:
                from backend.scripts.generate_synthetic import generate_adversarial_examples
            except ImportError:
                from scripts.generate_synthetic import generate_adversarial_examples

            features = dataset[self.feature_names].values
            labels = dataset["label"].values
            num_synthetic = int(len(dataset) * self.synthetic_ratio)
            synthetic_features, synthetic_labels = generate_adversarial_examples(features, labels, num_synthetic)
            import numpy as np
            import pandas as pd
            # Merge
            merged_features = np.vstack([features, synthetic_features])
            merged_labels = np.hstack([labels, synthetic_labels])
            dataset = pd.DataFrame(merged_features, columns=self.feature_names)
            dataset["label"] = merged_labels

        features = dataset[self.feature_names].values
        labels: Sequence[int] = dataset["label"].astype(int).tolist()

        pipeline = VulnerabilityPipeline()
        pipeline.fit(features, labels, self.feature_names)
        return TrainingArtifact(pipeline=pipeline, dataset_size=len(dataset))
