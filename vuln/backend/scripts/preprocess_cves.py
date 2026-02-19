
import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

def preprocess_cves(in_csv="../data/web_cves_raw.csv", out_csv="../data/web_cves_processed.csv", tfidf_path="../artifacts/tfidf_vectorizer.joblib"):
    df = pd.read_csv(in_csv)
    # Feature extraction: length, keyword counts, entropy, etc.
    df["desc_length"] = df["description"].apply(lambda x: len(str(x)))
    df["num_keywords"] = df["description"].apply(lambda x: sum([kw in str(x).lower() for kw in ["sql", "xss", "csrf", "cookie", "session", "http", "javascript", "php", "jsp", "html"]]))
    df["num_digits"] = df["description"].apply(lambda x: len(re.findall(r"\d", str(x))))
    df["cvssScore"] = pd.to_numeric(df["cvssScore"], errors="coerce").fillna(0)
    # Severity encoding
    severity_map = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "Unknown": -1, "": -1}
    df["severity"] = df["severity"].fillna("Unknown")
    df["severity_encoded"] = df["severity"].map(lambda x: severity_map.get(str(x).upper(), -1))
    # CWE encoding (simple hash or label encoding)
    df["cwe"] = df["cwe"].fillna("") if "cwe" in df.columns else ""
    df["cwe_encoded"] = df["cwe"].astype(str).apply(lambda x: abs(hash(x)) % 10000 if x else 0)
    # TF-IDF vectorization of description
    tfidf = TfidfVectorizer(max_features=100)
    tfidf_matrix = tfidf.fit_transform(df["description"].fillna("")).toarray()
    tfidf_feature_names = [f"tfidf_{name}" for name in tfidf.get_feature_names_out()]
    tfidf_df = pd.DataFrame(tfidf_matrix, columns=tfidf_feature_names)
    df = pd.concat([df.reset_index(drop=True), tfidf_df.reset_index(drop=True)], axis=1)
    joblib.dump(tfidf, tfidf_path)
    print(f"TF-IDF vectorizer saved to {tfidf_path}")
    # Ensure at least one numeric feature
    numeric_cols = df.select_dtypes(include=["number"]).columns
    if len(numeric_cols) == 0:
        df["dummy_numeric"] = 0
    df.to_csv(out_csv, index=False)
    print(f"Preprocessed CVEs saved to {out_csv}")


if __name__ == "__main__":
    import argparse
    import os
    parser = argparse.ArgumentParser(description="Preprocess CVE data with TF-IDF features.")
    default_data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    default_artifacts_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
    parser.add_argument("--in_csv", type=str, default=os.path.join(default_data_dir, "web_cves_raw.csv"), help="Input CSV file")
    parser.add_argument("--out_csv", type=str, default=os.path.join(default_data_dir, "web_cves_processed.csv"), help="Output CSV file")
    parser.add_argument("--tfidf_path", type=str, default=os.path.join(default_artifacts_dir, "tfidf_vectorizer.joblib"), help="Path to save TF-IDF vectorizer")
    args = parser.parse_args()
    preprocess_cves(args.in_csv, args.out_csv, args.tfidf_path)
