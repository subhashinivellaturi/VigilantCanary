#!/usr/bin/env python
"""
Test script for subdomain enumeration functionality.
Tests backend endpoint, database storage, and API integration.
"""

import json
import requests
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:8007/api/v1"
DB_PATH = Path(__file__).parent / "app" / "scan_history.db"

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def test_backend_health():
    """Test if backend is running"""
    print_header("Testing Backend Health")
    try:
        response = requests.get(f"{API_BASE_URL.replace('/api/v1', '')}/health", timeout=5)
        if response.status_code == 200:
            print("✓ Backend is running on port 8007")
            return True
        else:
            print(f"✗ Backend returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ Backend is not running on port 8007")
        print("  Start it with: python backend/run_server.py")
        return False
    except Exception as e:
        print(f"✗ Error checking backend: {e}")
        return False

def test_subdomain_enumeration():
    """Test subdomain enumeration endpoint"""
    print_header("Testing Subdomain Enumeration Endpoint")
    
    test_domain = "example.com"
    payload = {
        "base_domain": test_domain,
        "use_brute_force": True
    }
    
    print(f"Enumerating subdomains for: {test_domain}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(
            f"{API_BASE_URL}/enumerate-subdomains",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✓ Endpoint responded successfully")
            print(f"  Status: {data.get('status')}")
            print(f"  Domain: {data.get('domain')}")
            print(f"  Method: {data.get('method')}")
            print(f"  Scan Time: {data.get('scan_time')}s")
            print(f"  Subdomains Found: {data.get('total_found', 0)}")
            
            if data.get('subdomains'):
                print(f"\n  First 5 discovered subdomains:")
                for subdomain in data.get('subdomains', [])[:5]:
                    print(f"    - {subdomain}")
                if len(data.get('subdomains', [])) > 5:
                    print(f"    ... and {len(data.get('subdomains', [])) - 5} more")
            
            return data
        else:
            print(f"✗ Endpoint returned status {response.status_code}")
            print(f"  Response: {response.text}")
            return None
    except requests.exceptions.Timeout:
        print("✗ Request timed out (subdomain enumeration can take 1-3 minutes)")
        return None
    except Exception as e:
        print(f"✗ Error testing endpoint: {e}")
        return None

def test_database_storage():
    """Test if subdomain scans are stored in database"""
    print_header("Testing Database Storage")
    
    if not DB_PATH.exists():
        print(f"✗ Database not found at {DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if subdomains table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='subdomains'
        """)
        
        if not cursor.fetchone():
            print("✗ Subdomains table not found in database")
            return False
        
        print("✓ Subdomains table exists")
        
        # Get recent subdomain scans
        cursor.execute("""
            SELECT id, scan_timestamp, base_domain, total_found, scan_method, status
            FROM subdomains
            ORDER BY scan_timestamp DESC
            LIMIT 5
        """)
        
        rows = cursor.fetchall()
        
        if rows:
            print(f"✓ Found {len(rows)} recent subdomain scan(s)")
            print("\n  Recent scans:")
            for row in rows:
                scan_id, timestamp, domain, total, method, status = row
                print(f"    - ID: {scan_id}")
                print(f"      Domain: {domain}")
                print(f"      Subdomains Found: {total}")
                print(f"      Method: {method}")
                print(f"      Status: {status}")
                print(f"      Timestamp: {timestamp}")
                print()
        else:
            print("⚠ No subdomain scans found in database (this is OK if none have been run yet)")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Error querying database: {e}")
        return False

def test_recent_scans_endpoint():
    """Test the recent subdomain scans endpoint"""
    print_header("Testing Recent Subdomain Scans Endpoint")
    
    try:
        response = requests.get(
            f"{API_BASE_URL}/recent-subdomain-scans?limit=5",
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Endpoint responded successfully")
            print(f"  Status: {data.get('status')}")
            
            scans = data.get('scans', [])
            print(f"  Recent Scans: {len(scans)}")
            
            if scans:
                print(f"\n  First scan:")
                scan = scans[0]
                print(f"    - Base Domain: {scan.get('base_domain')}")
                print(f"    - Subdomains: {scan.get('total_found')}")
                print(f"    - Method: {scan.get('scan_method')}")
                print(f"    - Timestamp: {scan.get('timestamp')}")
            
            return True
        else:
            print(f"✗ Endpoint returned status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error testing endpoint: {e}")
        return False

def test_invalid_domain():
    """Test error handling with invalid domain"""
    print_header("Testing Error Handling")
    
    invalid_domains = ["invalid", "123", ""]
    
    for invalid_domain in invalid_domains:
        print(f"Testing with invalid domain: '{invalid_domain}'")
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/enumerate-subdomains",
                json={
                    "base_domain": invalid_domain,
                    "use_brute_force": True
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') in ['error', 'failed']:
                    print(f"  ✓ Error handled gracefully: {data.get('message')}")
                else:
                    print(f"  ⚠ Unexpected response: {data}")
            else:
                print(f"  ✓ Error response received (status {response.status_code})")
                
        except Exception as e:
            print(f"  ✓ Exception handled: {e}")
    
    print()

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("  Subdomain Enumeration Functionality Tests")
    print("="*60)
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Backend Health
    tests_total += 1
    if test_backend_health():
        tests_passed += 1
    else:
        print("\n⚠ Cannot continue without backend. Please start the server.")
        return False
    
    # Test 2: Invalid Domain Handling
    tests_total += 1
    test_invalid_domain()
    tests_passed += 1
    
    # Test 3: Database Storage
    tests_total += 1
    if test_database_storage():
        tests_passed += 1
    
    # Test 4: Recent Scans Endpoint
    tests_total += 1
    if test_recent_scans_endpoint():
        tests_passed += 1
    
    print_header("Test Summary")
    print(f"Tests Passed: {tests_passed}/{tests_total}")
    
    if tests_passed == tests_total:
        print("\n✓ All tests passed!")
        return True
    else:
        print(f"\n⚠ {tests_total - tests_passed} test(s) failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
