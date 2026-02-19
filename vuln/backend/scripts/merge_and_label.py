
import pandas as pd
import os
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

def merge_and_label_datasets(
    vuln_csv="../data/web_cves_processed.csv",
    normal_csv="../data/normal_samples.csv",
    out_train="../data/train.csv",
    out_test="../data/test.csv",
    test_size=0.2,
    random_state=42
):
    # Load and label vulnerable samples (NVD CVEs)
    df_vuln = pd.read_csv(vuln_csv)
    df_vuln["label"] = 1

    # Load and label normal/non-vulnerable samples
    if os.path.exists(normal_csv):
        df_normal = pd.read_csv(normal_csv)
        df_normal["label"] = 0
        # Add missing columns to normal samples
        for col in df_vuln.columns:
            if col not in df_normal.columns:
                if df_vuln[col].dtype.kind in 'biufc':
                    df_normal[col] = 0
                else:
                    df_normal[col] = ""
        # Ensure column order matches
        df_normal = df_normal[df_vuln.columns]
        df = pd.concat([df_vuln, df_normal], ignore_index=True)
    else:
        print(f"Warning: {normal_csv} not found. Attempting to auto-generate normal samples...")
        try:
            import subprocess
            subprocess.run(["python", os.path.join(os.path.dirname(__file__), "fetch_data.py")], check=True)
            if os.path.exists(normal_csv):
                df_normal = pd.read_csv(normal_csv)
                df_normal["label"] = 0
                for col in df_vuln.columns:
                    if col not in df_normal.columns:
                        if df_vuln[col].dtype.kind in 'biufc':
                            df_normal[col] = 0
                        else:
                            df_normal[col] = ""
                df_normal = df_normal[df_vuln.columns]
                df = pd.concat([df_vuln, df_normal], ignore_index=True)
            else:
                print("Auto-generation failed. Using only vulnerable samples.")
                df = df_vuln
        except Exception as e:
            print(f"Auto-generation failed: {e}. Using only vulnerable samples.")
            df = df_vuln


    # Remove duplicates based on description
    df = df.drop_duplicates(subset=["description"]).reset_index(drop=True)
    print("Removed duplicates. Dataset size:", len(df))

    # Print class distribution before split
    print("Class distribution before split:")
    print(df["label"].value_counts())

    # Stratified train-test split
    if len(df["label"].unique()) > 1:
        train_df, test_df = train_test_split(
            df, test_size=test_size, stratify=df["label"], random_state=random_state
        )
    else:
        print("Fail-safe: Only one class present. Aborting split and training.")
        raise ValueError("Dataset contains only one class. Please check data sources.")

    train_df.to_csv(out_train, index=False)
    test_df.to_csv(out_test, index=False)
    print(f"Train set: {len(train_df)} samples, Test set: {len(test_df)} samples.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Merge and label vulnerable and normal samples.")
    import os
    default_data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    parser.add_argument("--vuln_csv", type=str, default=os.path.join(default_data_dir, "web_cves_processed.csv"), help="Vulnerable samples CSV")
    parser.add_argument("--normal_csv", type=str, default=os.path.join(default_data_dir, "normal_samples.csv"), help="Normal samples CSV")
    parser.add_argument("--out_train", type=str, default=os.path.join(default_data_dir, "train.csv"), help="Output train CSV")
    parser.add_argument("--out_test", type=str, default=os.path.join(default_data_dir, "test.csv"), help="Output test CSV")
    parser.add_argument("--test_size", type=float, default=0.2, help="Test set size fraction")
    parser.add_argument("--random_state", type=int, default=42, help="Random state for splitting")
    args = parser.parse_args()
    merge_and_label_datasets(args.vuln_csv, args.normal_csv, args.out_train, args.out_test, args.test_size, args.random_state)
