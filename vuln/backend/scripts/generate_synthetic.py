#!/usr/bin/env python3
"""
Synthetic Data Generation for Vulnerability Detection

This script generates synthetic adversarial examples to augment the training dataset,
addressing the limitation of data quality and quantity mentioned in the base papers.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple

def generate_adversarial_examples(features: np.ndarray, labels: np.ndarray, num_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic adversarial examples by perturbing existing samples.
    
    Args:
        features: Original feature matrix
        labels: Original labels
        num_samples: Number of synthetic samples to generate
        
    Returns:
        Tuple of (synthetic_features, synthetic_labels)
    """
    np.random.seed(42)
    
    # Select samples to perturb (focus on vulnerable ones)
    vuln_indices = np.where(labels == 1)[0]
    if len(vuln_indices) == 0:
        vuln_indices = np.arange(len(labels))
    
    synthetic_features = []
    synthetic_labels = []
    
    for _ in range(num_samples):
        # Randomly select a base sample
        base_idx = np.random.choice(vuln_indices)
        base_sample = features[base_idx].copy()
        
        # Apply adversarial perturbations
        perturbation = np.random.normal(0, 0.1, size=base_sample.shape)
        perturbed_sample = base_sample + perturbation
        
        # Ensure non-negative values for certain features
        perturbed_sample = np.maximum(perturbed_sample, 0)
        
        synthetic_features.append(perturbed_sample)
        synthetic_labels.append(1)  # All synthetic samples are vulnerable
    
    return np.array(synthetic_features), np.array(synthetic_labels)

def augment_dataset(input_file: str, output_file: str, synthetic_ratio: float = 0.5):
    """
    Augment the dataset with synthetic examples.
    
    Args:
        input_file: Path to original dataset CSV
        output_file: Path to save augmented dataset
        synthetic_ratio: Ratio of synthetic to original samples
    """
    # Load original dataset
    df = pd.read_csv(input_file)
    
    # Assume last column is label
    features = df.iloc[:, :-1].values
    labels = df.iloc[:, -1].values
    
    # Generate synthetic data
    num_synthetic = int(len(df) * synthetic_ratio)
    synthetic_features, synthetic_labels = generate_adversarial_examples(features, labels, num_synthetic)
    
    # Combine original and synthetic
    augmented_features = np.vstack([features, synthetic_features])
    augmented_labels = np.hstack([labels, synthetic_labels])
    
    # Create augmented dataframe
    augmented_df = pd.DataFrame(augmented_features, columns=df.columns[:-1])
    augmented_df[df.columns[-1]] = augmented_labels
    
    # Save augmented dataset
    augmented_df.to_csv(output_file, index=False)
    print(f"Augmented dataset saved to {output_file}")
    print(f"Original samples: {len(df)}, Synthetic samples: {num_synthetic}, Total: {len(augmented_df)}")

if __name__ == "__main__":
    # Example usage for CLI
    import sys
    if len(sys.argv) != 3:
        print("Usage: python generate_synthetic.py <input_csv> <output_csv>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    augment_dataset(input_file, output_file)