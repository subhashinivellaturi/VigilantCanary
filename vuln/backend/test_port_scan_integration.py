#!/usr/bin/env python
"""
Integration test for port scanning feature.
Tests the complete workflow: API endpoint → port scanner → database → retrieval
"""

import sys
import json
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

from app.services.port_scanner import port_scanner, PortScanner
from app.services.scan_history import scan_db
from app.models.schemas import PortScanRequest, PortScanResponse, OpenPort


def test_port_scanner_service():
    """Test the port scanner service directly."""
    print("\n" + "="*60)
    print("TEST 1: Port Scanner Service")
    print("="*60)
    
    try:
        # Test with localhost - should find common services
        print(f"\n[*] Scanning localhost for common ports...")
        results = port_scanner.scan_ports('127.0.0.1', ports=[22, 80, 443, 3306, 8080])
        
        print(f"[+] Scan completed successfully!")
        print(f"    Results: {len(results)} ports checked")
        
        for result in results:
            status_icon = "[OPEN]" if result.state == "open" else "[CLOSED]"
            print(f"    {status_icon} Port {result.port}: {result.state} ({result.service})")
        
        return True
    except Exception as e:
        print(f"[-] Port scanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database_persistence():
    """Test saving and retrieving port scans from database."""
    print("\n" + "="*60)
    print("TEST 2: Database Persistence")
    print("="*60)
    
    try:
        # Create test data
        target = "test-target.local"
        scanned_ports = [21, 22, 80, 443, 3306]
        open_ports = [
            {"port": 80, "service": "http", "state": "open"},
            {"port": 443, "service": "https", "state": "open"}
        ]
        
        print(f"\n[*] Saving port scan to database...")
        print(f"    Target: {target}")
        print(f"    Scanned ports: {scanned_ports}")
        print(f"    Open ports: {len(open_ports)}")
        
        # Save to database
        scan_db.save_port_scan(
            target_host=target,
            scanned_ports=scanned_ports,
            open_ports=open_ports,
            scan_method="test_script",
            status="completed"
        )
        
        print(f"[+] Port scan saved successfully!")
        
        # Retrieve from database
        print(f"\n[*] Retrieving recent port scans...")
        recent = scan_db.get_recent_port_scans(limit=5)
        
        print(f"[+] Retrieved {len(recent)} recent scans")
        
        for scan in recent[:3]:
            print(f"\n    Scan: {scan.get('target_host', 'Unknown')}")
            print(f"    Time: {scan.get('scan_timestamp', 'N/A')}")
            print(f"    Method: {scan.get('scan_method', 'N/A')}")
            print(f"    Total scanned: {scan.get('total_scanned', len(scan.get('scanned_ports', [])))}")
            open_count = len(scan.get('open_ports', []))
            print(f"    Open ports: {open_count}")
            if scan.get('open_ports'):
                for port in scan.get('open_ports', [])[:3]:
                    print(f"        - Port {port['port']}: {port['service']}")
        
        return True
    except Exception as e:
        print(f"[-] Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_schema_validation():
    """Test Pydantic schema validation."""
    print("\n" + "="*60)
    print("TEST 3: Schema Validation")
    print("="*60)
    
    try:
        print(f"\n[*] Testing PortScanRequest validation...")
        request = PortScanRequest(target="example.com", ports=[80, 443])
        print(f"[+] Valid request created: {request.target}")
        
        print(f"\n[*] Testing OpenPort schema...")
        port = OpenPort(port=443, service="https", state="open")
        print(f"[+] Valid port object created: {port.port}/{port.service}")
        
        print(f"\n[*] Testing PortScanResponse validation...")
        response = PortScanResponse(
            scan_id="test-123",
            target_host="example.com",
            scan_timestamp="2024-01-01T12:00:00Z",
            scanned_ports=[80, 443],
            open_ports=[
                {"port": 443, "service": "https", "state": "open"}
            ],
            total_scanned=2,
            open_count=1,
            status="completed",
            severity="low",
            message="Test scan completed",
            disclaimer="Test only"
        )
        print(f"[+] Valid response object created with {response.open_count} open ports")
        
        return True
    except Exception as e:
        print(f"[-] Schema validation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_endpoint_simulation():
    """Simulate the API endpoint logic."""
    print("\n" + "="*60)
    print("TEST 4: API Endpoint Logic Simulation")
    print("="*60)
    
    try:
        print(f"\n[*] Simulating POST /api/v1/scan-ports endpoint...")
        
        # Simulate request
        request_data = PortScanRequest(target="localhost", ports=[22, 80, 443])
        
        print(f"    Request: scan {request_data.target}")
        print(f"    Ports to scan: {request_data.ports if request_data.ports else port_scanner.COMMON_PORTS}")
        
        # Simulate port scan
        target = request_data.target.strip()
        ports = request_data.ports if request_data.ports else port_scanner.COMMON_PORTS
        results = port_scanner.scan_ports(target, ports=ports)
        open_ports_list = [r for r in results if r.state == 'open']
        open_port_objects = [
            {"port": p.port, "service": p.service, "state": p.state}
            for p in open_ports_list
        ]
        
        # Simulate database save
        scan_db.save_port_scan(target, ports, open_port_objects, 
                               "nmap" if port_scanner.nmap_available else "socket", "completed")
        
        print(f"[+] Endpoint simulation completed!")
        print(f"    Found {len(open_ports_list)} open ports")
        print(f"    Saved to database")
        
        return True
    except Exception as e:
        print(f"[-] API endpoint test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("\n" + "="*60)
    print("PORT SCANNING FEATURE - INTEGRATION TESTS")
    print("="*60)
    
    results = {
        "Port Scanner Service": test_port_scanner_service(),
        "Database Persistence": test_database_persistence(),
        "Schema Validation": test_schema_validation(),
        "API Endpoint Logic": test_api_endpoint_simulation(),
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status:10} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("="*60)
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
