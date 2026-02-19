from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import PortScanRequest
from app.services.scan_history import scan_db
import time

client = TestClient(app)


def test_port_scan_and_history():

    # Clean up any existing port scans (test isolation)
    import sqlite3
    db_path = scan_db.db_path
    with sqlite3.connect(db_path) as conn:
        conn.execute('DELETE FROM port_scans')
        conn.commit()

    # Submit a new port scan
    scan_request = {
        "target": "scanme.nmap.org",
        "ports": [22, 80],
        "scan_type": "tcp"
    }
    from app.config import get_settings
    settings = get_settings()
    prefix = settings.api_prefix
    resp = client.post(f"{prefix}/port-scan", json=scan_request)
    print('Port scan API response:', resp.json())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "scan_id" in data
    scan_id = data["scan_id"]

    # Wait for scan to be stored (simulate async if needed)
    time.sleep(0.5)

    # Check recent port scans
    resp_recent = client.get(f"{prefix}/recent-port-scans")
    assert resp_recent.status_code == 200
    recent = resp_recent.json()
    assert recent["status"] == "success"
    scans = recent["scans"]
    assert isinstance(scans, list)
    found = any(str(scan_id) == str(scan.get("id")) for scan in scans)
    assert found, "Port scan should appear in recent scans"

    # Delete the scan
    resp_delete = client.delete(f"{prefix}/scan/{scan_id}")
    print('Deleted scan status:', resp_delete.status_code)
    assert resp_delete.status_code == 204

    # Check recent port scans again
    resp_recent2 = client.get(f"{prefix}/recent-port-scans")
    assert resp_recent2.status_code == 200
    recent2 = resp_recent2.json()
    assert recent2["status"] == "success"
    scans2 = recent2["scans"]
    found2 = any(str(scan_id) == str(scan.get("id")) for scan in scans2)
    print('Recent scans after delete:', scans2)
    assert not found2, "Port scan should be deleted from recent scans"

    # Clean up after test
    with sqlite3.connect(db_path) as conn:
        conn.execute('DELETE FROM port_scans')
        conn.commit()
