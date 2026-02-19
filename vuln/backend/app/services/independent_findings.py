"""
Production-grade independent vulnerability finding generator.
Detects and reports each vulnerability type independently with:
- OWASP severity alignment
- CVSS-style scoring
- Duplicate detection and removal
- Scan mode tracking (passive vs active)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict
from datetime import datetime, timezone, timedelta


class VulnerabilityType(Enum):
    """All independent vulnerability types."""
    INSECURE_HTTP = "insecure_http"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    OPEN_DIRECTORY = "open_directory"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    CSRF = "csrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    UNKNOWN = "unknown"


class OWASPSeverity(Enum):
    """OWASP standard severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanMode(Enum):
    """Track whether scanning was passive or active."""
    PASSIVE_ONLY = "passive_only"
    ACTIVE_WITH_PAYLOAD = "active_with_payload"


# OWASP severity mapping for each vulnerability type
VULNERABILITY_SEVERITY_MAP = {
    VulnerabilityType.INSECURE_HTTP: OWASPSeverity.MEDIUM,
    VulnerabilityType.MISSING_SECURITY_HEADERS: OWASPSeverity.MEDIUM,
    VulnerabilityType.OPEN_DIRECTORY: OWASPSeverity.MEDIUM,
    VulnerabilityType.XSS: OWASPSeverity.HIGH,  # Reflected/Stored XSS is High
    VulnerabilityType.SQL_INJECTION: OWASPSeverity.CRITICAL,
    VulnerabilityType.CSRF: OWASPSeverity.HIGH,
    VulnerabilityType.PATH_TRAVERSAL: OWASPSeverity.HIGH,
    VulnerabilityType.COMMAND_INJECTION: OWASPSeverity.CRITICAL,
    VulnerabilityType.UNKNOWN: OWASPSeverity.LOW,  # Safe summary
}

# CVSS score ranges for severity calculation
CVSS_SEVERITY_RANGES = {
    (0.0, 3.9): OWASPSeverity.LOW,
    (4.0, 6.9): OWASPSeverity.MEDIUM,
    (7.0, 8.9): OWASPSeverity.HIGH,
    (9.0, 10.0): OWASPSeverity.CRITICAL,
}

def calculate_severity_from_cvss(cvss_score: float) -> OWASPSeverity:
    """Calculate severity based on CVSS score ranges."""
    for (min_score, max_score), severity in CVSS_SEVERITY_RANGES.items():
        if min_score <= cvss_score <= max_score:
            return severity
    return OWASPSeverity.MEDIUM  # Default fallback

# CVSS scoring guidance for each vulnerability (0-10)
VULNERABILITY_CVSS_BASE = {
    VulnerabilityType.INSECURE_HTTP: 5.3,  # Medium - Allows eavesdropping
    VulnerabilityType.MISSING_SECURITY_HEADERS: 5.8,  # Medium - Increases XSS/clickjacking risk
    VulnerabilityType.OPEN_DIRECTORY: 5.3,  # Medium - Information disclosure
    VulnerabilityType.XSS: 8.2,  # High - Can lead to account compromise
    VulnerabilityType.SQL_INJECTION: 9.8,  # Critical - Complete database compromise
    VulnerabilityType.CSRF: 8.8,  # High - Unauthorized state-changing actions
    VulnerabilityType.PATH_TRAVERSAL: 7.5,  # High - Unauthorized file access
    VulnerabilityType.COMMAND_INJECTION: 9.8,  # Critical - Remote code execution
    VulnerabilityType.UNKNOWN: 0.0,  # Safe - No vulnerability
}

# Remediation steps for each vulnerability type
VULNERABILITY_REMEDIATIONS = {
    VulnerabilityType.INSECURE_HTTP: [
        "Deploy an SSL/TLS certificate (use Let's Encrypt for free)",
        "Redirect all HTTP traffic to HTTPS (HTTP Status 301/302)",
        "Set Strict-Transport-Security (HSTS) header with appropriate max-age",
        "Enable HSTS preloading for critical domains",
    ],
    VulnerabilityType.MISSING_SECURITY_HEADERS: [
        "Implement HTTP Strict-Transport-Security (HSTS) header with appropriate max-age",
        "Set Strict-Transport-Security max-age to at least 31536000 (1 year) for production",
        "Add Content-Security-Policy (CSP) header to prevent XSS",
        "Set X-Frame-Options: SAMEORIGIN or DENY to prevent clickjacking",
        "Add X-Content-Type-Options: nosniff to prevent MIME sniffing",
        "Add Referrer-Policy to control information leakage",
    ],
    VulnerabilityType.OPEN_DIRECTORY: [
        "Disable directory listing in web server configuration",
        "Move sensitive files outside the web root",
        "Implement authentication for sensitive endpoints",
        "Use server/application configuration to restrict access (do NOT rely on robots.txt)",
        "Deploy Web Application Firewall (WAF) rules to block unauthorized access attempts",
        "Enable access logging and monitoring for suspicious activity",
    ],
    VulnerabilityType.XSS: [
        "Escape/encode all user input before rendering in HTML",
        "Use Content Security Policy (CSP) headers",
        "Implement input validation on both client and server",
        "Use templating engines with auto-escaping enabled",
        "Sanitize HTML input using libraries like DOMPurify or bleach",
    ],
    VulnerabilityType.SQL_INJECTION: [
        "Use parameterized queries (prepared statements) for ALL database queries",
        "NEVER concatenate user input into SQL strings",
        "Implement input validation and type checking",
        "Apply principle of least privilege to database accounts",
        "Use an ORM that properly escapes queries",
    ],
    VulnerabilityType.CSRF: [
        "Implement CSRF tokens in all state-changing requests (POST, PUT, DELETE)",
        "Store tokens server-side and regenerate after authentication",
        "Validate token on every state-changing request",
        "Use SameSite cookie attribute (SameSite=Strict for sensitive operations)",
        "Implement double-submit cookie pattern as additional protection",
    ],
    VulnerabilityType.PATH_TRAVERSAL: [
        "Never trust user input for file paths",
        "Use path whitelisting to restrict allowed directories",
        "Canonicalize file paths and validate against allowed locations",
        "Use os.path.abspath() and verify the result is within allowed directory",
        "Run application with minimal file system permissions",
    ],
    VulnerabilityType.COMMAND_INJECTION: [
        "NEVER use shell=True or system() with user input",
        "Use parameterized system calls or API functions",
        "Implement strict input validation and whitelisting",
        "Use subprocess.run() with list arguments instead of strings",
        "Run application with minimal system privileges (non-root user)",
    ],
    VulnerabilityType.UNKNOWN: [
        "Continue regular security monitoring and testing",
        "Keep security libraries and frameworks updated",
        "Implement security headers and best practices",
        "Perform regular security audits and penetration testing",
    ],
}

# OWASP references for each vulnerability
VULNERABILITY_OWASP_REFS = {
    VulnerabilityType.INSECURE_HTTP: "OWASP A02:2021 - Cryptographic Failures",
    VulnerabilityType.MISSING_SECURITY_HEADERS: "OWASP A05:2021 - Security Misconfiguration",
    VulnerabilityType.OPEN_DIRECTORY: "OWASP A05:2021 - Security Misconfiguration",
    VulnerabilityType.XSS: "OWASP A03:2021 - Injection (Reflected/Stored XSS)",
    VulnerabilityType.SQL_INJECTION: "OWASP A03:2021 - Injection",
    VulnerabilityType.CSRF: "OWASP A01:2021 - Broken Access Control",
    VulnerabilityType.PATH_TRAVERSAL: "OWASP A01:2021 - Broken Access Control",
    VulnerabilityType.COMMAND_INJECTION: "OWASP A03:2021 - Injection",
    VulnerabilityType.UNKNOWN: "Security Assessment - No vulnerabilities detected",
}


@dataclass
class IndependentFinding:
    """A single, independent vulnerability finding."""
    finding_id: str
    vulnerability_type: VulnerabilityType
    severity: OWASPSeverity
    cvss_score: float
    confidence: float
    description: str
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    http_method: str = "GET"
    payload_used: Optional[str] = None
    payload_result: Optional[str] = None
    remediation_steps: List[str] = field(default_factory=list)
    owasp_reference: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None


@dataclass
class ExecutiveSummary:
    """Executive-level summary for reporting."""
    scan_timestamp: str
    scanned_url: str
    scan_mode: ScanMode
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_status: str  # "SAFE", "SUSPICIOUS", "UNSAFE"
    risk_score_0_to_100: int
    executive_summary_text: str
    remediation_priority: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_timestamp": self.scan_timestamp,
            "scanned_url": self.scanned_url,
            "scan_mode": self.scan_mode.value,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "overall_risk_status": self.overall_risk_status,
            "risk_score_0_to_100": self.risk_score_0_to_100,
            "executive_summary_text": self.executive_summary_text,
            "remediation_priority": self.remediation_priority,
        }


class IndependentFindingsGenerator:
    """Generates production-grade independent vulnerability findings."""

    def __init__(self):
        self.findings: List[IndependentFinding] = []
        self.finding_counter = 0

    def add_finding(
        self,
        vuln_type: VulnerabilityType,
        description: str,
        affected_url: Optional[str] = None,
        affected_parameter: Optional[str] = None,
        http_method: str = "GET",
        payload_used: Optional[str] = None,
        payload_result: Optional[str] = None,
        confidence: float = 80.0,
        severity_override: Optional[str] = None,
        is_safe_summary: bool = False,
    ) -> None:
        """Add a vulnerability finding."""
        self.finding_counter += 1
        finding_id = f"FIND-{self.finding_counter:04d}"
        
        # Determine severity based on CVSS score ranges
        if severity_override:
            severity_map = {
                "critical": OWASPSeverity.CRITICAL,
                "high": OWASPSeverity.HIGH,
                "medium": OWASPSeverity.MEDIUM,
                "low": OWASPSeverity.LOW,
            }
            severity = severity_map.get(severity_override.lower(), calculate_severity_from_cvss(cvss_score))
        else:
            severity = calculate_severity_from_cvss(cvss_score)
        
        # Get CVSS score
        cvss_score = VULNERABILITY_CVSS_BASE.get(vuln_type, 5.0)
        
        # Get remediation steps
        remediation_steps = VULNERABILITY_REMEDIATIONS.get(vuln_type, [])
        
        # Get OWASP reference
        owasp_reference = VULNERABILITY_OWASP_REFS.get(vuln_type)
        
        finding = IndependentFinding(
            finding_id=finding_id,
            vulnerability_type=vuln_type,
            severity=severity,
            cvss_score=cvss_score,
            confidence=confidence,
            description=description,
            affected_url=affected_url,
            affected_parameter=affected_parameter,
            http_method=http_method,
            payload_used=payload_used,
            payload_result=payload_result,
            remediation_steps=remediation_steps,
            owasp_reference=owasp_reference,
        )
        
        self.findings.append(finding)

    @staticmethod
    def _get_ist_timestamp() -> str:
        """Get current timestamp in IST (UTC+5:30)."""
        ist = timezone(timedelta(hours=5, minutes=30))
        return datetime.now(ist).isoformat()

    def remove_duplicates(self) -> List[IndependentFinding]:
        """
        Remove duplicate findings (same type, same URL, same parameter).
        Marks duplicates with is_duplicate=True and duplicate_of pointing to original.
        Returns deduplicated findings (only non-duplicates).
        """
        seen = {}
        deduplicated = []
        
        for finding in self.findings:
            key = (
                finding.vulnerability_type.value,
                finding.affected_url or "",
                finding.affected_parameter or "",
            )
            
            if key not in seen:
                # First occurrence - keep it
                seen[key] = finding
                deduplicated.append(finding)
            else:
                # Duplicate - mark it
                finding.is_duplicate = True
                finding.duplicate_of = seen[key].finding_id
        
        # Update findings list to reflect deduplication
        self.findings = [f for f in self.findings if not f.is_duplicate]
        return deduplicated

    def generate_executive_summary(
        self,
        scanned_url: str,
        scan_mode: ScanMode,
    ) -> ExecutiveSummary:
        """Generate executive summary from current findings."""
        
        # Filter out safe summary findings for risk assessment
        risk_findings = [f for f in self.findings if f.vulnerability_type.value != "unknown"]
        safe_summary_findings = [f for f in self.findings if f.vulnerability_type.value == "unknown"]
        
        # Count by severity for risk findings only
        critical_count = sum(1 for f in risk_findings if f.severity == OWASPSeverity.CRITICAL)
        high_count = sum(1 for f in risk_findings if f.severity == OWASPSeverity.HIGH)
        medium_count = sum(1 for f in risk_findings if f.severity == OWASPSeverity.MEDIUM)
        low_count = sum(1 for f in risk_findings if f.severity == OWASPSeverity.LOW)
        
        total_risk_findings = len(risk_findings)
        total_findings = len(self.findings)  # Include safe summary
        
        # Determine overall risk status based on risk findings only
        if critical_count > 0 or high_count > 0:
            overall_risk_status = "UNSAFE"
            risk_score = max(70, critical_count * 20 + high_count * 15)
            remediation_priority = "Immediate" if critical_count > 0 else "High"
        elif medium_count > 0:
            overall_risk_status = "UNSAFE"
            risk_score = 50 + medium_count * 10
            remediation_priority = "Medium"
        elif low_count > 0:
            overall_risk_status = "UNSAFE"
            risk_score = 30 + low_count * 5
            remediation_priority = "Low"
        else:
            overall_risk_status = "SAFE"
            risk_score = 0
            remediation_priority = "None required"
        
        # Scan mode label
        scan_mode_label = "Active" if scan_mode == ScanMode.ACTIVE_WITH_PAYLOAD else "Passive"
        
        # Generate executive summary text
        if overall_risk_status == "SAFE":
            exec_summary = (
                f"Website {scanned_url} passed the {scan_mode_label} security scan. "
                f"No security vulnerabilities were detected. "
                f"The input appears safe based on comprehensive analysis."
            )
        else:  # UNSAFE
            total_vulns = critical_count + high_count + medium_count + low_count
            exec_summary = (
                f"Website {scanned_url} has {total_vulns} security vulnerabilities detected "
                f"(Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}). "
                f"Immediate remediation is required to prevent exploitation. "
                f"Priority: {remediation_priority}."
            )
        
        return ExecutiveSummary(
            scan_timestamp=self._get_ist_timestamp(),
            scanned_url=scanned_url,
            scan_mode=scan_mode,
            total_findings=total_findings,  # Include safe summary in total
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            overall_risk_status=overall_risk_status,
            risk_score_0_to_100=risk_score,
            executive_summary_text=exec_summary,
            remediation_priority=remediation_priority,
        )

    def get_finding_counts_by_type(self) -> Dict[str, int]:
        """Get count of findings grouped by vulnerability type."""
        counts = {}
        for finding in self.findings:
            type_name = finding.vulnerability_type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts

    def get_findings_by_type(self) -> Dict[str, List[IndependentFinding]]:
        """Get findings grouped by vulnerability type."""
        grouped = {}
        for finding in self.findings:
            type_name = finding.vulnerability_type.value
            if type_name not in grouped:
                grouped[type_name] = []
            grouped[type_name].append(finding)
        return grouped

    def to_response_dict(
        self,
        scanned_url: str,
        scan_mode: ScanMode,
    ) -> Dict:
        """Convert findings to response dictionary."""
        
        # Remove duplicates before generating response
        self.remove_duplicates()
        
        # Generate summary
        executive_summary = self.generate_executive_summary(scanned_url, scan_mode)
        
        # Convert findings to dict
        findings_list = []
        for finding in self.findings:
            findings_list.append({
                "finding_id": finding.finding_id,
                "vulnerability_type": finding.vulnerability_type.value,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
                "confidence": finding.confidence,
                "description": finding.description,
                "affected_url": finding.affected_url,
                "affected_parameter": finding.affected_parameter,
                "http_method": finding.http_method,
                "payload_used": finding.payload_used,
                "payload_result": finding.payload_result,
                "remediation_steps": finding.remediation_steps,
                "owasp_reference": finding.owasp_reference,
                "is_duplicate": finding.is_duplicate,
                "duplicate_of": finding.duplicate_of,
            })
        
        # Severity breakdown - count ALL findings by severity for dashboard purposes
        all_critical = sum(1 for f in self.findings if f.severity == OWASPSeverity.CRITICAL)
        all_high = sum(1 for f in self.findings if f.severity == OWASPSeverity.HIGH)
        all_medium = sum(1 for f in self.findings if f.severity == OWASPSeverity.MEDIUM)
        all_low = sum(1 for f in self.findings if f.severity == OWASPSeverity.LOW)
        
        severity_breakdown = {
            "critical": all_critical,
            "high": all_high,
            "medium": all_medium,
            "low": all_low,
        }
        
        return {
            "scan_timestamp": executive_summary.scan_timestamp,
            "scanned_url": scanned_url,
            "scan_mode": scan_mode.value,
            "findings": findings_list,
            "finding_counts": self.get_finding_counts_by_type(),
            "severity_breakdown": severity_breakdown,
            "executive_summary": executive_summary.to_dict(),
            "disclaimer": "⚠️ Automated scanning results may require manual verification by security professionals for production systems.",
            "notes": "Each finding is reported independently. Duplicate findings have been removed.",
        }
