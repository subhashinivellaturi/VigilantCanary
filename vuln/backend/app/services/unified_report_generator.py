"""
Unified Security Report Generation Service

Generates comprehensive security reports in multiple formats:
- PDF (via JSON + client-side generation or server-side)
- CSV (with full Unicode support)
- JSON (structured data format)

Includes scan summaries, severity breakdowns, open ports,
discovered subdomains, and vulnerabilities detected.
"""

import json
import csv
import io
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import unicodedata


@dataclass
class ScanSummary:
    """Scan summary data"""
    total_scans: int
    last_scan_date: str
    scan_timestamp: str
    total_vulnerabilities: int
    total_ports_scanned: int
    total_subdomains_found: int


@dataclass
class SeverityBreakdown:
    """Severity statistics"""
    critical: int
    high: int
    medium: int
    low: int
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class UnifiedReportGenerator:
    """Generate unified security reports in multiple formats"""

    def __init__(self):
        """Initialize the report generator"""
        self.report_data = {}

    def normalize_unicode(self, text: Optional[str]) -> str:
        """Normalize Unicode text for proper display and encoding"""
        if not text:
            return ""
        
        # Convert to string if needed
        text = str(text)
        
        # Normalize to NFC form (composed characters)
        normalized = unicodedata.normalize('NFC', text)
        
        # Replace problematic characters
        normalized = normalized.replace('\x00', '')  # Remove null bytes
        normalized = normalized.replace('\r\n', '\n')  # Normalize line endings
        
        return normalized

    def escape_csv_field(self, field: Any) -> str:
        """Escape a field value for CSV output"""
        field_str = str(field) if field is not None else ""
        field_str = self.normalize_unicode(field_str)
        
        # Quote if contains comma, newline, or quote
        if ',' in field_str or '\n' in field_str or '"' in field_str:
            field_str = '"' + field_str.replace('"', '""') + '"'
        
        return field_str

    def generate_json_report(
        self,
        summary: Dict[str, Any],
        severity_breakdown: Dict[str, int],
        vulnerabilities: List[Dict[str, Any]],
        port_scans: List[Dict[str, Any]],
        subdomain_scans: List[Dict[str, Any]],
        recent_scans: List[Dict[str, Any]]
    ) -> str:
        """Generate a JSON format report with full Unicode support"""
        
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_version": "1.0",
                "format": "json",
                "encoding": "utf-8"
            },
            "scan_summary": {
                "total_scans": len(recent_scans),
                "last_scan_date": summary.get("last_scan_date", ""),
                "total_vulnerabilities": len(vulnerabilities),
                "total_ports_scanned": len(port_scans),
                "total_subdomains_found": sum(s.get("total_found", 0) for s in subdomain_scans)
            },
            "severity_breakdown": self.normalize_severity_breakdown(severity_breakdown),
            "vulnerabilities": [
                self._normalize_vulnerability(v) for v in vulnerabilities
            ],
            "port_scans": [
                self._normalize_port_scan(p) for p in port_scans
            ],
            "subdomain_scans": [
                self._normalize_subdomain_scan(s) for s in subdomain_scans
            ],
            "recent_scans": [
                self._normalize_recent_scan(r) for r in recent_scans
            ]
        }
        
        # Ensure proper UTF-8 encoding
        return json.dumps(report, ensure_ascii=False, indent=2)

    def generate_csv_report(
        self,
        summary: Dict[str, Any],
        severity_breakdown: Dict[str, int],
        vulnerabilities: List[Dict[str, Any]],
        port_scans: List[Dict[str, Any]],
        subdomain_scans: List[Dict[str, Any]],
        recent_scans: List[Dict[str, Any]]
    ) -> str:
        """Generate a CSV format report with full Unicode support"""
        
        output = io.StringIO()
        
        # Write BOM for UTF-8 (helps with Excel compatibility)
        output.write('\ufeff')
        
        # Title and generation info
        output.write("Unified Security Report\n")
        output.write(f"Generated: {datetime.now().isoformat()}\n")
        output.write(f"Report Version: 1.0\n\n")
        
        # Executive Summary
        output.write("EXECUTIVE SUMMARY\n")
        output.write("Metric,Value\n")
        writer = csv.writer(output)
        
        summary_data = [
            ["Total Scans", len(recent_scans)],
            ["Total Vulnerabilities", len(vulnerabilities)],
            ["Critical", severity_breakdown.get("critical", 0)],
            ["High", severity_breakdown.get("high", 0)],
            ["Medium", severity_breakdown.get("medium", 0)],
            ["Low", severity_breakdown.get("low", 0)],
            ["Open Ports Detected", len(port_scans)],
            ["Subdomains Discovered", sum(s.get("total_found", 0) for s in subdomain_scans)]
        ]
        
        for row in summary_data:
            output.write(f"{self.escape_csv_field(row[0])},{self.escape_csv_field(row[1])}\n")
        
        output.write("\n")
        
        # Severity Breakdown
        output.write("SEVERITY BREAKDOWN\n")
        output.write("Severity,Count\n")
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_breakdown.get(severity, 0)
            output.write(f"{severity.capitalize()},{count}\n")
        
        output.write("\n")
        
        # Vulnerabilities
        if vulnerabilities:
            output.write("DETECTED VULNERABILITIES\n")
            output.write("Vulnerability Name,Severity,Affected URL,CVSS Score,Confidence,Description,Scan Type,Timestamp\n")
            
            for vuln in vulnerabilities:
                row = [
                    vuln.get("vulnerability_name", ""),
                    vuln.get("severity", ""),
                    vuln.get("affected_url", ""),
                    vuln.get("cvss_score", ""),
                    vuln.get("confidence", ""),
                    vuln.get("description", ""),
                    vuln.get("scan_type", ""),
                    vuln.get("timestamp", "")
                ]
                # Normalize and escape each field
                normalized_row = [self.normalize_unicode(str(f)) for f in row]
                escaped_row = [self.escape_csv_field(f) for f in normalized_row]
                output.write(",".join(escaped_row) + "\n")
            
            output.write("\n")
        
        # Port Scans
        if port_scans:
            output.write("OPEN PORTS DETECTED\n")
            output.write("Target Host,Open Count,Ports,Scan Method,Timestamp\n")
            
            for scan in port_scans:
                ports_str = "; ".join(
                    f"{p.get('port')}/{p.get('protocol')}({p.get('service')})"
                    for p in scan.get("open_ports", [])
                )
                row = [
                    scan.get("target_host", ""),
                    scan.get("open_count", 0),
                    ports_str,
                    scan.get("scan_method", ""),
                    scan.get("timestamp", "")
                ]
                normalized_row = [self.normalize_unicode(str(f)) for f in row]
                escaped_row = [self.escape_csv_field(f) for f in normalized_row]
                output.write(",".join(escaped_row) + "\n")
            
            output.write("\n")
        
        # Subdomain Scans
        if subdomain_scans:
            output.write("DISCOVERED SUBDOMAINS\n")
            output.write("Base Domain,Total Found,Sample Subdomains,Scan Method,Status,Timestamp\n")
            
            for scan in subdomain_scans:
                subdomains = "; ".join(scan.get("discovered_subdomains", [])[:5])
                if len(scan.get("discovered_subdomains", [])) > 5:
                    subdomains += f"; ... and {len(scan.get('discovered_subdomains', [])) - 5} more"
                
                row = [
                    scan.get("base_domain", ""),
                    scan.get("total_found", 0),
                    subdomains,
                    scan.get("scan_method", ""),
                    scan.get("status", ""),
                    scan.get("timestamp", "")
                ]
                normalized_row = [self.normalize_unicode(str(f)) for f in row]
                escaped_row = [self.escape_csv_field(f) for f in normalized_row]
                output.write(",".join(escaped_row) + "\n")
        
        return output.getvalue()

    def generate_html_report(
        self,
        summary: Dict[str, Any],
        severity_breakdown: Dict[str, int],
        vulnerabilities: List[Dict[str, Any]],
        port_scans: List[Dict[str, Any]],
        subdomain_scans: List[Dict[str, Any]],
        recent_scans: List[Dict[str, Any]]
    ) -> str:
        """Generate an HTML report for preview or direct viewing"""
        
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Security Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 32px;
        }
        .header p {
            margin: 5px 0 0 0;
            opacity: 0.9;
        }
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
            color: #667eea;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-card .label {
            font-size: 14px;
            opacity: 0.9;
        }
        .severity-bar {
            display: flex;
            height: 40px;
            border-radius: 4px;
            overflow: hidden;
            margin: 20px 0;
        }
        .severity-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }
        .critical { background: #ef4444; }
        .high { background: #f97316; }
        .medium { background: #eab308; }
        .low { background: #10b981; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background: #f0f0f0;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #ddd;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background: #f9f9f9;
        }
        .vulnerability-item {
            margin: 15px 0;
            padding: 15px;
            border-left: 4px solid #667eea;
            background: #f9f9f9;
            border-radius: 4px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin: 0 4px 0 0;
        }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #fed7aa; color: #92400e; }
        .badge-medium { background: #fef3c7; color: #78350f; }
        .badge-low { background: #dcfce7; color: #15803d; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Unified Security Report</h1>
        <p>Generated: {generated_at}</p>
    </div>
"""
        
        # Executive Summary
        html += f"""
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Scans</div>
                <div class="value">{len(recent_scans)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Vulnerabilities</div>
                <div class="value">{len(vulnerabilities)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Open Ports</div>
                <div class="value">{len(port_scans)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Subdomains Found</div>
                <div class="value">{sum(s.get('total_found', 0) for s in subdomain_scans)}</div>
            </div>
        </div>
    </div>
"""
        
        # Severity Breakdown
        total_vulns = len(vulnerabilities)
        if total_vulns > 0:
            critical = severity_breakdown.get("critical", 0)
            high = severity_breakdown.get("high", 0)
            medium = severity_breakdown.get("medium", 0)
            low = severity_breakdown.get("low", 0)
            
            html += f"""
    <div class="section">
        <h2>Severity Breakdown</h2>
        <div class="severity-bar">
            <div class="severity-segment critical" style="width: {(critical/total_vulns)*100:.1f}%">
                {critical} Critical
            </div>
            <div class="severity-segment high" style="width: {(high/total_vulns)*100:.1f}%">
                {high} High
            </div>
            <div class="severity-segment medium" style="width: {(medium/total_vulns)*100:.1f}%">
                {medium} Medium
            </div>
            <div class="severity-segment low" style="width: {(low/total_vulns)*100:.1f}%">
                {low} Low
            </div>
        </div>
    </div>
"""
        
        # Vulnerabilities
        if vulnerabilities:
            html += """
    <div class="section">
        <h2>Detected Vulnerabilities</h2>
"""
            for vuln in vulnerabilities[:20]:  # Limit to first 20
                severity_class = vuln.get("severity", "low").lower()
                html += f"""
        <div class="vulnerability-item">
            <span class="badge badge-{severity_class}">{vuln.get('severity', '').upper()}</span>
            <strong>{self.normalize_unicode(str(vuln.get('vulnerability_name', 'Unknown')))}</strong>
            <p><small>CVSS: {vuln.get('cvss_score', 'N/A')} | Confidence: {vuln.get('confidence', 'N/A')}%</small></p>
            <p><small>URL: {self.normalize_unicode(str(vuln.get('affected_url', 'N/A')))}</small></p>
        </div>
"""
            if len(vulnerabilities) > 20:
                html += f"""
        <p><em>... and {len(vulnerabilities) - 20} more vulnerabilities</em></p>
"""
            html += """
    </div>
"""
        
        # Port Scans
        if port_scans:
            html += """
    <div class="section">
        <h2>Open Ports Detected</h2>
        <table>
            <thead>
                <tr>
                    <th>Target Host</th>
                    <th>Open Ports</th>
                    <th>Scan Method</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
"""
            for scan in port_scans[:10]:
                ports = ", ".join(
                    f"{p.get('port')}/{p.get('protocol')}"
                    for p in scan.get("open_ports", [])[:5]
                )
                if len(scan.get("open_ports", [])) > 5:
                    ports += f" ... +{len(scan.get('open_ports', [])) - 5}"
                
                html += f"""
                <tr>
                    <td>{self.normalize_unicode(str(scan.get('target_host', 'N/A')))}</td>
                    <td>{ports}</td>
                    <td>{scan.get('scan_method', 'N/A')}</td>
                    <td>{scan.get('timestamp', 'N/A')}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </div>
"""
        
        html += f"""
    <div class="footer">
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} by Vigilant Canary Security Scanner</p>
        <p>Report Version: 1.0 | Encoding: UTF-8</p>
    </div>
</body>
</html>
"""
        
        return html.replace("{generated_at}", datetime.now().isoformat())

    def normalize_severity_breakdown(self, breakdown: Dict[str, int]) -> Dict[str, int]:
        """Normalize severity breakdown data"""
        return {
            "critical": breakdown.get("critical", 0),
            "high": breakdown.get("high", 0),
            "medium": breakdown.get("medium", 0),
            "low": breakdown.get("low", 0)
        }

    def _normalize_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize vulnerability data for export"""
        return {
            "id": vuln.get("id", ""),
            "vulnerability_name": self.normalize_unicode(vuln.get("vulnerability_name", "")),
            "severity": vuln.get("severity", "").lower(),
            "affected_url": self.normalize_unicode(vuln.get("affected_url", "")),
            "scan_type": vuln.get("scan_type", ""),
            "cvss_score": float(vuln.get("cvss_score", 0)),
            "confidence": float(vuln.get("confidence", 0)),
            "description": self.normalize_unicode(vuln.get("description", "")),
            "timestamp": vuln.get("timestamp", "")
        }

    def _normalize_port_scan(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize port scan data for export"""
        return {
            "id": scan.get("id", ""),
            "target_host": self.normalize_unicode(scan.get("target_host", "")),
            "open_count": scan.get("open_count", 0),
            "open_ports": [
                {
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": self.normalize_unicode(p.get("service", ""))
                }
                for p in scan.get("open_ports", [])
            ],
            "scan_method": scan.get("scan_method", ""),
            "timestamp": scan.get("timestamp", "")
        }

    def _normalize_subdomain_scan(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize subdomain scan data for export"""
        return {
            "id": scan.get("id", ""),
            "base_domain": self.normalize_unicode(scan.get("base_domain", "")),
            "total_found": scan.get("total_found", 0),
            "discovered_subdomains": [
                self.normalize_unicode(s) for s in scan.get("discovered_subdomains", [])
            ],
            "scan_method": scan.get("scan_method", ""),
            "status": scan.get("status", ""),
            "timestamp": scan.get("timestamp", "")
        }

    def _normalize_recent_scan(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize recent scan data for export"""
        return {
            "id": scan.get("id", ""),
            "scanned_url": self.normalize_unicode(scan.get("scanned_url", "")),
            "scan_mode": scan.get("scan_mode", ""),
            "status": scan.get("status", ""),
            "findings": scan.get("findings", 0),
            "timestamp": scan.get("timestamp", "")
        }


# Global instance
unified_report_generator = UnifiedReportGenerator()
