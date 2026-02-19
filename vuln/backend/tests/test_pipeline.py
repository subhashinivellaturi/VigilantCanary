import numpy as np

from app.services.pipeline import VulnerabilityPipeline


def test_pipeline_predicts_output_shape() -> None:
    pipeline = VulnerabilityPipeline()
    features = np.random.rand(20, 5)
    labels = np.array([0, 1] * 10)
    feature_names = [f"f{i}" for i in range(5)]

    pipeline.fit(features, labels, feature_names)
    sample = np.random.rand(1, 5)
    result = pipeline.predict(sample)

    assert result.label in {"safe", "vulnerable"}
    assert 0.0 <= result.probability <= 1.0
