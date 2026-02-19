"""Utility to export synthetic vulnerability datasets at arbitrary sizes."""
from __future__ import annotations

import argparse
from pathlib import Path

from app.services.trainer import VulnerabilityTrainer


def export(size: int, output: Path) -> Path:
    trainer = VulnerabilityTrainer(target_dataset_size=size)
    df = trainer.build_dataset()
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export synthetic vulnerability dataset")
    parser.add_argument("size", type=int, help="Number of rows to generate (e.g. 5000)")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("backend/data"),
        help="Directory or file path for CSV output",
    )
    parser.add_argument(
        "--filename",
        type=str,
        default=None,
        help="Optional explicit filename (defaults to dataset_<size>.csv)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = args.output
    if output_path.is_dir():
        filename = args.filename or f"dataset_{args.size}.csv"
        output_path = output_path / filename
    elif args.filename:
        raise ValueError("Do not provide --filename when --output points to a file")

    saved_path = export(args.size, output_path)
    print(f"Dataset with {args.size} rows written to {saved_path}")


if __name__ == "__main__":
    main()
