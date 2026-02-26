#!/usr/bin/env python3
"""
Test script to validate the fixed port scanning and history endpoints.
Ensures all issues are resolved for deployment.
"""

import json
import requests
from typing import Dict, List

# Configuration
API_BASE = "http://localhost:8007/api/v1"
TEST_TIMEOUT = 10

def test_health_check() -> bool:
    """Test that the API is running and healthy."""
    print("\n[TEST] Checking API health...")
    try:
        response = requests.get(f"{API_BASE}/health", timeout=TEST_TIMEOUT)
        print(f"  ✓ API is healthy: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ API health check failed: {e}")
        return False

def test_recent_scans() -> bool:
    """Test recent scans endpoint."""
    print("\n[TEST] Testing /recent-scans endpoint...")
    try:
        response = requests.get(f"{API_BASE}/recent-scans?limit=10", timeout=TEST_TIMEOUT)
        data = response.json()
        print(f"  ✓ Status: {response.status_code}")
        print(f"  ✓ Response has 'scans' key: {'scans' in data}")
        if isinstance(data.get('scans'), list):
            print(f"  ✓ Scans is a list with {len(data['scans'])} items")
            if len(data['scans']) > 0:
                first_scan = data['scans'][0]
                required_fields = ['id', 'timestamp', 'target_url', 'status']
                missing = [f for f in required_fields if f not in first_scan]
                if missing:
                    print(f"  ✗ Missing fields in scan: {missing}")
                else:
                    print(f"  ✓ All required fields present")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_recent_port_scans() -> bool:
    """Test recent port scans endpoint."""
    print("\n[TEST] Testing /recent-port-scans endpoint...")
    try:
        response = requests.get(f"{API_BASE}/recent-port-scans?limit=10", timeout=TEST_TIMEOUT)
        data = response.json()
        print(f"  ✓ Status: {response.status_code}")
        print(f"  ✓ Response has 'scans' key: {'scans' in data}")
        if isinstance(data.get('scans'), list):
            print(f"  ✓ Scans is a list with {len(data['scans'])} items")
            if len(data['scans']) > 0:
                first_scan = data['scans'][0]
                required_fields = ['id', 'timestamp', 'target_host']
                missing = [f for f in required_fields if f not in first_scan]
                if missing:
                    print(f"  ✗ Missing fields: {missing}")
                else:
                    print(f"  ✓ All required fields present")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_recent_subdomain_scans() -> bool:
    """Test recent subdomain scans endpoint."""
    print("\n[TEST] Testing /recent-subdomain-scans endpoint...")
    try:
        response = requests.get(f"{API_BASE}/recent-subdomain-scans?limit=10", timeout=TEST_TIMEOUT)
        data = response.json()
        print(f"  ✓ Status: {response.status_code}")
        print(f"  ✓ Response has 'scans' key: {'scans' in data}")
        if isinstance(data.get('scans'), list):
            print(f"  ✓ Scans is a list with {len(data['scans'])} items")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_port_scan_common_ports() -> bool:
    """Test port scanning with common ports."""
    print("\n[TEST] Testing port scan with common ports...")
    try:
        payload = {
            "target": "127.0.0.1",
            "ports": "21,22,80,443"
        }
        response = requests.post(
            f"{API_BASE}/scan-ports",
            json=payload,
            timeout=TEST_TIMEOUT
        )
        data = response.json()
        print(f"  ✓ Status: {response.status_code}")
        
        required_fields = ['scan_id', 'target_host', 'open_ports', 'total_scanned', 'open_count']
        missing = [f for f in required_fields if f not in data]
        if missing:
            print(f"  ✗ Missing fields: {missing}")
            return False
        else:
            print(f"  ✓ All required fields present")
            print(f"  ✓ Target: {data['target_host']}")
            print(f"  ✓ Scanned ports: {data['total_scanned']}")
            print(f"  ✓ Open ports: {data['open_count']}")
            if isinstance(data['open_ports'], list):
                print(f"  ✓ Open ports is a list")
        
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_port_scan_range() -> bool:
    """Test port scanning with port range."""
    print("\n[TEST] Testing port scan with range (1-100)...")
    try:
        payload = {
            "target": "127.0.0.1",
            "ports": "1-100"
        }
        response = requests.post(
            f"{API_BASE}/scan-ports",
            json=payload,
            timeout=TEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            print(f"  ✓ Status: {response.status_code}")
            print(f"  ✓ Scanned {data['total_scanned']} ports")
            print(f"  ✓ Found {data['open_count']} open ports")
        else:
            print(f"  ✗ Status: {response.status_code}")
            print(f"  Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_port_scan_default() -> bool:
    """Test port scanning with default ports."""
    print("\n[TEST] Testing port scan with default ports...")
    try:
        payload = {
            "target": "127.0.0.1"
        }
        response = requests.post(
            f"{API_BASE}/scan-ports",
            json=payload,
            timeout=TEST_TIMEOUT
        )
        data = response.json()
        print(f"  ✓ Status: {response.status_code}")
        print(f"  ✓ Scanned {data['total_scanned']} ports (defaults)")
        print(f"  ✓ Found {data['open_count']} open ports")
        return response.status_code == 200
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("VIGILANT CANARY - DEPLOYMENT VALIDATION TESTS")
    print("=" * 60)
    
    tests = [
        test_health_check,
        test_recent_scans,
        test_recent_port_scans,
        test_recent_subdomain_scans,
        test_port_scan_common_ports,
        test_port_scan_range,
        test_port_scan_default,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"\n✗ Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ All tests passed! System is ready for deployment.")
    else:
        print(f"\n✗ {total - passed} test(s) failed. Review errors above.")
    
    return passed == total

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)
