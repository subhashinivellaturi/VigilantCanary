import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from ..models.schemas import ProductionScanResponse

class ScanHistoryDB:
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan by its ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            return cursor.rowcount > 0

    def delete_port_scan(self, scan_id: int) -> bool:
        """Delete a port scan by its ID (soft delete)."""
        print(f"Deleting port scan: scan_id={scan_id}, type={type(scan_id)}")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('UPDATE port_scans SET status = "deleted" WHERE id = ?', (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_subdomain_scan(self, scan_id: int) -> bool:
        """Delete a subdomain scan by its ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('DELETE FROM subdomains WHERE id = ?', (scan_id,))
            return cursor.rowcount > 0
    def __init__(self, db_path: str = "scan_history.db"):
        self.db_path = Path(__file__).parent.parent.parent / db_path
        self.init_db()

    def init_db(self):
        """Initialize the database and create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            # Add status column if it doesn't exist
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    scanned_url TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    status TEXT DEFAULT 'completed',
                    findings TEXT NOT NULL,  -- JSON string of findings
                    severity_breakdown TEXT NOT NULL,  -- JSON string
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    overall_risk_status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL
                )
            ''')
            
            # Create port scans table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    scanned_ports TEXT NOT NULL,  -- JSON array of scanned ports
                    open_ports TEXT NOT NULL,  -- JSON array of open ports
                    scan_method TEXT NOT NULL,  -- 'nmap' or 'socket'
                    status TEXT DEFAULT 'completed'
                )
            ''')

            # Create subdomains table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    base_domain TEXT NOT NULL,
                    discovered_subdomains TEXT NOT NULL,  -- JSON array of subdomains
                    total_found INTEGER NOT NULL,
                    scan_method TEXT NOT NULL,
                    status TEXT DEFAULT 'completed'
                )
            ''')
            
            # Add status column to existing tables if it doesn't exist
            try:
                conn.execute('ALTER TABLE scans ADD COLUMN status TEXT DEFAULT "completed"')
            except sqlite3.OperationalError:
                # Column already exists
                pass

    def save_scan(self, scan_response: ProductionScanResponse, status: str = "completed"):
        """Save a scan result to the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                INSERT INTO scans (
                    scan_timestamp, scanned_url, scan_mode, status, findings,
                    severity_breakdown, total_findings, critical_count,
                    high_count, medium_count, low_count, overall_risk_status, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_response.scan_timestamp,
                scan_response.scanned_url,
                scan_response.scan_mode,
                status,
                json.dumps([finding.model_dump() for finding in scan_response.findings]),
                json.dumps(scan_response.severity_breakdown),
                len(scan_response.findings),  # Use actual findings count
                scan_response.severity_breakdown.get('critical', 0),
                scan_response.severity_breakdown.get('high', 0),
                scan_response.severity_breakdown.get('medium', 0),
                scan_response.severity_breakdown.get('low', 0),
                scan_response.executive_summary.overall_risk_status,
                scan_response.executive_summary.risk_score_0_to_100
            ))
            return cursor.lastrowid

    def get_severity_summary(self) -> Dict[str, int]:
        """Get total counts for each severity level across all scans."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT
                    SUM(critical_count) as critical,
                    SUM(high_count) as high,
                    SUM(medium_count) as medium,
                    SUM(low_count) as low
                FROM scans
            ''')
            row = cursor.fetchone()
            return {
                'critical': row[0] or 0,
                'high': row[1] or 0,
                'medium': row[2] or 0,
                'low': row[3] or 0
            }

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan summaries with detailed information."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT id, scan_timestamp, scanned_url, scan_mode, status, findings,
                       total_findings, overall_risk_status
                FROM scans
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            scans = []
            for row in cursor.fetchall():
                scan_id, timestamp, url, mode, status, findings_json, total_findings, risk_status = row
                
                # Parse findings to determine scan types
                scan_types = self._determine_scan_types(findings_json)
                
                scans.append({
                    'id': scan_id,
                    'timestamp': timestamp,
                    'target_url': url,
                    'scan_types': scan_types,
                    'status': status,
                    'total_findings': total_findings,
                    'risk_status': risk_status
                })
            
            return scans
    
    def _determine_scan_types(self, findings_json: str) -> List[str]:
        """Determine scan types from findings."""
        try:
            findings = json.loads(findings_json)
            types = set()
            
            for finding in findings:
                vuln_type = finding.get('vulnerability_type', '')
                if vuln_type == 'xss':
                    types.add('XSS')
                elif vuln_type == 'sql_injection':
                    types.add('SQLi')
                elif vuln_type == 'path_traversal':
                    types.add('Path Traversal')
                elif vuln_type == 'command_injection':
                    types.add('Command Injection')
                elif vuln_type == 'csrf':
                    types.add('CSRF')
                elif vuln_type in ['insecure_http', 'missing_security_headers', 'open_directory']:
                    types.add('Security Headers')
            
            # If no specific types found, determine from scan mode
            if not types:
                types.add('Vulnerability Scan')
            
            return sorted(list(types))
        except:
            return ['Vulnerability Scan']
    
    def save_port_scan(self, target_host: str, scanned_ports: List[int],
                      open_ports: List[Dict[str, Any]], scan_method: str,
                      status: str = "completed") -> int:
        """Save a port scan result to the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                INSERT INTO port_scans (
                    scan_timestamp, target_host, scanned_ports, open_ports,
                    scan_method, status
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                target_host,
                json.dumps(scanned_ports),
                json.dumps(open_ports),
                scan_method,
                status
            ))
            return cursor.lastrowid
    
    def get_recent_port_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent port scan results."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT id, scan_timestamp, target_host, scanned_ports,
                       open_ports, scan_method, status
                FROM port_scans
                WHERE status != 'deleted'
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (limit,))
            scans = []
            for row in cursor.fetchall():
                scan_id, timestamp, target, scanned_ports_json, open_ports_json, method, status = row
                try:
                    scanned_ports = json.loads(scanned_ports_json)
                    open_ports = json.loads(open_ports_json)
                except:
                    scanned_ports = []
                    open_ports = []
                scans.append({
                    'id': scan_id,
                    'timestamp': timestamp,
                    'target_host': target,
                    'scanned_ports': scanned_ports,
                    'open_ports': open_ports,
                    'scan_method': method,
                    'status': status,
                    'open_count': len(open_ports)
                })
            return scans

    def get_recent_vulnerabilities(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent individual vulnerabilities from scans."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT scan_timestamp, scanned_url, scan_mode, findings
                FROM scans
                WHERE total_findings > 0
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (limit * 2,))  # Get more scans to ensure we have enough vulnerabilities
            
            vulnerabilities = []
            for row in cursor.fetchall():
                timestamp, url, mode, findings_json = row
                
                try:
                    findings = json.loads(findings_json)
                    for finding in findings:
                        vulnerabilities.append({
                            'id': f"{timestamp}_{finding.get('finding_id', 'unknown')}",
                            'timestamp': timestamp,
                            'vulnerability_name': finding.get('vulnerability_type', 'Unknown'),
                            'severity': finding.get('severity', 'unknown').lower(),
                            'affected_url': finding.get('affected_url', url),
                            'scan_type': mode,
                            'cvss_score': finding.get('cvss_score', 0),
                            'description': finding.get('description', ''),
                            'confidence': finding.get('confidence', 0)
                        })
                except (json.JSONDecodeError, KeyError):
                    continue
            
            # Sort by severity (Critical -> High -> Medium -> Low) then by timestamp
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            vulnerabilities.sort(key=lambda x: (
                severity_order.get(x['severity'], 4),
                x['timestamp']
            ), reverse=True)
            
            return vulnerabilities[:limit]

    def get_cvss_summary(self) -> Dict[str, int]:
        """Calculate severity counts based on CVSS score ranges across all findings."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT findings FROM scans')
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for (findings_json,) in cursor.fetchall():
                try:
                    findings = json.loads(findings_json)
                    for finding in findings:
                        cvss = finding.get('cvss_score')
                        if cvss is None:
                            # Fall back to textual severity if no cvss provided
                            sev = (finding.get('severity') or '').lower()
                            if sev in counts:
                                counts[sev] += 1
                            continue
                        try:
                            score = float(cvss)
                        except Exception:
                            continue

                        # CVSS ranges (common mapping)
                        if score >= 9.0:
                            counts['critical'] += 1
                        elif score >= 7.0:
                            counts['high'] += 1
                        elif score >= 4.0:
                            counts['medium'] += 1
                        else:
                            counts['low'] += 1
                except Exception:
                    continue
            return counts

    def get_scan_by_id(self, scan_id: int) -> Dict[str, Any] | None:
        """Retrieve a single scan by its ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT id, scan_timestamp, scanned_url, scan_mode, status, findings, severity_breakdown,
                       total_findings, critical_count, high_count, medium_count, low_count, overall_risk_status, risk_score
                FROM scans
                WHERE id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            (scan_id, timestamp, url, mode, status, findings_json, severity_json,
             total_findings, critical_count, high_count, medium_count, low_count, risk_status, risk_score) = row

            try:
                findings = json.loads(findings_json)
            except json.JSONDecodeError:
                findings = []

            try:
                severity_breakdown = json.loads(severity_json)
            except json.JSONDecodeError:
                severity_breakdown = {
                    'critical': critical_count or 0,
                    'high': high_count or 0,
                    'medium': medium_count or 0,
                    'low': low_count or 0
                }

            return {
                'id': scan_id,
                'scan_timestamp': timestamp,
                'scanned_url': url,
                'scan_mode': mode,
                'status': status,
                'findings': findings,
                'severity_breakdown': severity_breakdown,
                'total_findings': total_findings,
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'overall_risk_status': risk_status,
                'risk_score': risk_score,
            }

    def save_subdomain_scan(self, base_domain: str, discovered_subdomains: List[str],
                           scan_method: str = 'dns_brute_force') -> int:
        """Save subdomain scan results to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                INSERT INTO subdomains (
                    scan_timestamp, base_domain, discovered_subdomains,
                    total_found, scan_method, status
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                base_domain,
                json.dumps(discovered_subdomains),
                len(discovered_subdomains),
                scan_method,
                'completed'
            ))
            return cursor.lastrowid

    def get_recent_subdomain_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent subdomain scan results."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT id, scan_timestamp, base_domain, discovered_subdomains,
                       total_found, scan_method, status
                FROM subdomains
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (limit,))

            scans = []
            for row in cursor.fetchall():
                scan_id, timestamp, base_domain, subdomains_json, total_found, method, status = row

                try:
                    discovered_subdomains = json.loads(subdomains_json)
                except json.JSONDecodeError:
                    discovered_subdomains = []

                scans.append({
                    'id': scan_id,
                    'timestamp': timestamp,
                    'base_domain': base_domain,
                    'discovered_subdomains': discovered_subdomains,
                    'total_found': total_found,
                    'scan_method': method,
                    'status': status
                })

            return scans

# Global instance
scan_db = ScanHistoryDB()