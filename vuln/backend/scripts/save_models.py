import joblib

LGB_MODEL_PATH = "../artifacts/lightgbm_cve.joblib"
IF_MODEL_PATH = "../artifacts/isolation_forest_cve.joblib"


def save_models():
    # Models are already saved in train_models.py using joblib
    print(f"Models saved at {LGB_MODEL_PATH} and {IF_MODEL_PATH}")

if __name__ == "__main__":
    save_models()
