import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.over_sampling import SMOTE
import joblib
import logging
import os

def feature_engineering(df):
    df["desc_length"] = df["description"].apply(lambda x: len(str(x)))
    df["num_keywords"] = df["description"].apply(lambda x: sum([kw in str(x).lower() for kw in ["sql", "xss", "csrf", "cookie", "session", "http", "javascript", "php", "jsp", "html"]]))
    df["num_digits"] = df["description"].apply(lambda x: len(re.findall(r"\d", str(x))))
    df["cvssScore"] = pd.to_numeric(df["cvssScore"], errors="coerce").fillna(0)
    severity_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "Unknown": -1, "": -1}
    df["severity"] = df["severity"].fillna("Unknown")
    df["severity_encoded"] = df["severity"].map(lambda x: severity_map.get(str(x).upper(), -1))
    df["cwe"] = df["cwe"].fillna("") if "cwe" in df.columns else ""
    df["cwe_encoded"] = df["cwe"].astype(str).apply(lambda x: abs(hash(x)) % 10000 if x else 0)
    return df

def preprocess_and_balance(train_csv, test_csv, out_train, out_test, tfidf_path, random_state=42):
    logging.basicConfig(level=logging.INFO)
    train_df = pd.read_csv(train_csv)
    test_df = pd.read_csv(test_csv)
    train_df = feature_engineering(train_df)
    test_df = feature_engineering(test_df)
    # Fit TF-IDF only on train
    tfidf = TfidfVectorizer(max_features=100)
    tfidf_matrix_train = tfidf.fit_transform(train_df["description"].fillna("")).toarray()
    tfidf_matrix_test = tfidf.transform(test_df["description"].fillna("")).toarray()
    tfidf_feature_names = [f"tfidf_{name}" for name in tfidf.get_feature_names_out()]
    tfidf_df_train = pd.DataFrame(tfidf_matrix_train, columns=tfidf_feature_names)
    tfidf_df_test = pd.DataFrame(tfidf_matrix_test, columns=tfidf_feature_names)
    # Drop any overlapping tfidf columns before concatenation to avoid duplicates
    overlap_cols = set(train_df.columns) & set(tfidf_feature_names)
    if overlap_cols:
        train_df = train_df.drop(columns=list(overlap_cols))
        test_df = test_df.drop(columns=list(overlap_cols))
    train_df = pd.concat([train_df.reset_index(drop=True), tfidf_df_train.reset_index(drop=True)], axis=1)
    test_df = pd.concat([test_df.reset_index(drop=True), tfidf_df_test.reset_index(drop=True)], axis=1)
    joblib.dump(tfidf, tfidf_path)
    logging.info(f"TF-IDF vectorizer saved to {tfidf_path}")
    # SMOTE only on train
    feature_cols = [col for col in train_df.select_dtypes(include=["number"]).columns if col not in ["id", "label"]]
    # Remove duplicate columns if any
    from collections import OrderedDict
    feature_cols = list(OrderedDict.fromkeys(feature_cols))
    # Assign X_train after deduplication of feature_cols
    X_train = train_df[feature_cols]
    X_train = train_df[feature_cols]
    y_train = train_df["label"]
    print("Class distribution before SMOTE:")
    print(y_train.value_counts())
    imbalance_threshold = 2.0
    class_counts = y_train.value_counts()
    if len(class_counts) == 2 and (class_counts.max() / class_counts.min()) > imbalance_threshold:
        n_minority = class_counts.min()
        if n_minority > 1:
            k_neighbors = min(5, n_minority - 1)
            if k_neighbors >= 1:
                print(f"Applying SMOTE to training data with k_neighbors={k_neighbors}...")
                smote = SMOTE(random_state=random_state, k_neighbors=k_neighbors)
                X_res, y_res = smote.fit_resample(X_train, y_train)
                assert X_res.shape[1] == len(feature_cols), f"Shape mismatch: X_res has {X_res.shape[1]} columns, feature_cols has {len(feature_cols)}"
                train_df_bal = pd.DataFrame(X_res, columns=feature_cols)
                train_df_bal["label"] = y_res
                # Only keep numeric features and label after SMOTE
                train_df = train_df_bal
                print("Class distribution after SMOTE:")
                print(train_df["label"].value_counts())
            else:
                print("Not enough minority samples for SMOTE. Skipping SMOTE.")
        else:
            print("Not enough minority samples for SMOTE. Skipping SMOTE.")
    train_df.to_csv(out_train, index=False)
    test_df.to_csv(out_test, index=False)
    print(f"Saved balanced train set to {out_train}, test set to {out_test}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Preprocess and balance train/test splits with TF-IDF and SMOTE.")
    parser.add_argument("--train_csv", type=str, required=True)
    parser.add_argument("--test_csv", type=str, required=True)
    parser.add_argument("--out_train", type=str, required=True)
    parser.add_argument("--out_test", type=str, required=True)
    parser.add_argument("--tfidf_path", type=str, required=True)
    args = parser.parse_args()
    preprocess_and_balance(args.train_csv, args.test_csv, args.out_train, args.out_test, args.tfidf_path)
