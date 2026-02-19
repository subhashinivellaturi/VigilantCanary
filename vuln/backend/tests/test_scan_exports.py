from fastapi.testclient import TestClient
from app.main import app
from app.services.scan_history import scan_db
from app.models.schemas import ProductionScanResponse, IndependentFinding, ExecutiveSummary

client = TestClient(app)


def make_scan_response():
    finding = IndependentFinding(
        finding_id="f1",
        vulnerability_type="sql_injection",
        severity="high",
        cvss_score=8.5,
        confidence=90.0,
        description="Test SQLi",
        affected_url="http://example.com/test"
    )
    exec_summary = ExecutiveSummary(
        scan_timestamp="2023-01-01T00:00:00Z",
        scanned_url="http://example.com/test",
        scan_mode="passive_only",
        total_findings=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        overall_risk_status="High",
        risk_score_0_to_100=80,
        executive_summary_text="One high severity finding",
        remediation_priority="Immediate"
    )
    scan_response = ProductionScanResponse(
        scan_timestamp="2023-01-01T00:00:00Z",
        scanned_url="http://example.com/test",
        scan_mode="passive_only",
        findings=[finding],
        finding_counts={"sql_injection": 1},
        severity_breakdown={"critical": 0, "high": 1, "medium": 0, "low": 0},
        executive_summary=exec_summary
    )
    return scan_response


def test_scan_export_json_and_csv():
    # Save a fake scan
    scan_response = make_scan_response()
    scan_id = scan_db.save_scan(scan_response, status="completed")

    from app.config import get_settings
    settings = get_settings()

    # Fetch scan by id
    resp = client.get(f"{settings.api_prefix}/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["scan"]["id"] == scan_id
    assert data["scan"]["scanned_url"] == "http://example.com/test"

    # Export JSON
    resp_json = client.get(f"{settings.api_prefix}/scans/{scan_id}/export?format=json")
    assert resp_json.status_code == 200
    assert resp_json.headers.get("content-type") == "application/json"
    assert f"\"scanned_url\": \"http://example.com/test\"" in resp_json.text

    # Export CSV
    resp_csv = client.get(f"{settings.api_prefix}/scans/{scan_id}/export?format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers.get("content-type")
    assert "finding_id,vulnerability_type,severity" in resp_csv.text
    assert "f1" in resp_csv.text