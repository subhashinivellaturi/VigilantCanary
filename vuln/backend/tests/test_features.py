from app.services.features import FeatureBundle, extract_features, shannon_entropy


def test_extract_features_returns_expected_length() -> None:
    bundle: FeatureBundle = extract_features(
        "https://example.com/search?q=test",
        "q=test&sort=asc",
    )
    assert len(bundle.values) == len(bundle.labels) == 17


def test_entropy_increases_with_variety() -> None:
    low = shannon_entropy("aaaaaa")
    high = shannon_entropy("abcdef")
    assert high > low
