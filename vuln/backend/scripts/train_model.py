from __future__ import annotations

from pathlib import Path

import joblib

from app.services.trainer import VulnerabilityTrainer


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Train vulnerability detection model")
    parser.add_argument('--use_synthetic', action='store_true', help='Use synthetic/adversarial data augmentation')
    parser.add_argument('--synthetic_ratio', type=float, default=0.5, help='Ratio of synthetic to real samples (default: 0.5)')
    args = parser.parse_args()

    trainer = VulnerabilityTrainer(use_synthetic=args.use_synthetic, synthetic_ratio=args.synthetic_ratio)
    artifact = trainer.train()
    model_dir = Path(__file__).resolve().parent.parent / "artifacts"
    model_dir.mkdir(exist_ok=True)
    joblib.dump(artifact.pipeline, model_dir / "pipeline.joblib")
    print(f"Saved pipeline with {artifact.dataset_size} rows")


if __name__ == "__main__":
    main()
