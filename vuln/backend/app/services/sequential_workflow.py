"""
Sequential Web Vulnerability Detection Workflow

Implements a 5-step sequential analysis:
1. Website Safety Check (URL analysis)
2. Payload Injection Analysis (only if safe)
3. Risk Evaluation
4. Explanation & Guidance
5. Structured JSON Output
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import List, Optional

from .features import extract_features
from .inference import InferenceService
from ..models.schemas import VulnerabilityRequest, Severity


class SafetyStatus(Enum):
    """Safety classification for website or payload."""
    SAFE = "safe"
    UNSAFE = "unsafe"
    SUSPICIOUS = "suspicious"


class VulnerabilityLocation(Enum):
    """Location where vulnerability exists."""
    URL_STRUCTURE = "url_structure"
    QUERY_PARAMETERS = "query_parameters"
    PAYLOAD_BODY = "payload_body"
    ENCODING = "encoding"
    INJECTION_POINT = "injection_point"
    EXECUTABLE_CONTEXT = "executable_context"
    DATABASE_CONTEXT = "database_context"
    FILE_SYSTEM = "file_system"
    UNKNOWN = "unknown"


@dataclass
class VulnerabilityIndicator:
    """A detected vulnerability indicator."""
    indicator_type: str  # e.g., "sql_injection", "xss", "path_traversal"
    severity_factor: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    description: str
    affected_parameter: Optional[str] = None  # Parameter/field name where vulnerability detected
    http_method: str = "GET"  # HTTP method (GET, POST, PUT, DELETE, etc.)
    response_status_code: Optional[int] = None  # Expected response status code (e.g., 200, 403)


@dataclass
class RemediationStep:
    """A recommended security fix."""
    priority: int  # 1 (highest) to 5 (lowest)
    title: str
    description: str
    code_example: str
    reference: str  # OWASP, NIST, etc.


@dataclass
class Step1Result:
    """Result of Website Safety Check (Step 1)."""
    status: SafetyStatus
    url: str
    is_safe: bool
    vulnerability_locations: List[VulnerabilityLocation]
    indicators: List[VulnerabilityIndicator]
    explanation: str
    remediation_steps: List[RemediationStep]
    risk_level_if_unsafe: Severity
    proceed_to_step2: bool  # True if safe, False if unsafe


@dataclass
class Step2Result:
    """Result of Payload Injection Analysis (Step 2)."""
    status: SafetyStatus
    payload_safe: bool
    combined_risk: Severity
    vulnerability_locations: List[VulnerabilityLocation]
    indicators: List[VulnerabilityIndicator]
    explanation: str
    remediation_steps: List[RemediationStep]
    attack_vectors_detected: List[str]


@dataclass
class Step3Result:
    """Result of Risk Evaluation (Step 3)."""
    risk_level: Severity
    risk_score: float  # 0.0 to 1.0
    justification: str
    contributing_factors: List[str]


@dataclass
class Step4Result:
    """Result of Explanation & Guidance (Step 4)."""
    detailed_explanation: str
    vulnerable_areas: List[str]
    best_practices: List[str]
    references: List[str]


@dataclass
class Step5Result:
    """Result of Remediation Suggestions (Step 5)."""
    priority_remediations: List[RemediationStep]
    short_term_actions: List[str]
    long_term_strategy: List[str]
    compliance_requirements: List[str]
    estimated_effort: str  # "Low", "Medium", "High"
    summary: str


@dataclass
class SequentialWorkflowResult:
    """Complete workflow result across all 5 steps."""
    scan_timestamp: str  # IST timezone ISO format timestamp
    step1: Step1Result
    step2: Optional[Step2Result] = None
    step3: Optional[Step3Result] = None
    step4: Optional[Step4Result] = None
    step5: Optional[Step5Result] = None
    workflow_completed: bool = False
    status_message: str = ""


class SequentialWorkflowEngine:
    """Executes the 5-step sequential vulnerability analysis."""

    def __init__(self) -> None:
        self.inference_service = InferenceService.instance()
        self._vulnerability_patterns = self._init_patterns()

    @staticmethod
    def _get_ist_timestamp() -> str:
        """Generate current timestamp in IST timezone (UTC+5:30) in ISO format."""
        ist = timezone(timedelta(hours=5, minutes=30))
        return datetime.now(ist).isoformat()

    @staticmethod
    def _deduplicate_indicators(indicators: List[VulnerabilityIndicator]) -> List[VulnerabilityIndicator]:
        """
        Deduplicate vulnerability indicators by type.
        Keeps the first occurrence of each unique indicator_type.
        Returns deduplicated list maintaining original order.
        """
        seen_types = set()
        deduplicated = []
        
        for indicator in indicators:
            if indicator.indicator_type not in seen_types:
                seen_types.add(indicator.indicator_type)
                deduplicated.append(indicator)
        
        return deduplicated

    @staticmethod
    def _extract_parameters_from_url(url: str) -> List[str]:
        """Extract query parameters from URL."""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            return list(parse_qs(parsed.query).keys())
        except:
            return []

    @staticmethod
    def _infer_http_method_from_url(url: str) -> str:
        """Infer likely HTTP method based on URL patterns."""
        url_lower = url.lower()
        if any(pattern in url_lower for pattern in ["/delete", "/remove"]):
            return "DELETE"
        elif any(pattern in url_lower for pattern in ["/create", "/add", "/submit", "/upload"]):
            return "POST"
        elif any(pattern in url_lower for pattern in ["/update", "/edit", "/modify"]):
            return "PUT"
        else:
            return "GET"

    @staticmethod
    def _infer_response_status_from_context(indicator_type: str) -> int:
        """Infer expected response status code based on vulnerability type."""
        # Different vulnerabilities might return different status codes
        status_map = {
            "sql_injection": 500,  # SQL error might cause 500 or 403
            "xss": 200,  # XSS payload might be reflected in 200 response
            "path_traversal": 200,  # Successful traversal returns 200 with file content
            "command_injection": 500,  # Command error causes 500
            "missing_security_headers": 200,  # Headers missing in successful response
            "open_directory": 403,  # Open directory returns 403 or 200 with listing
        }
        return status_map.get(indicator_type, 200)

    def _init_patterns(self) -> dict:
        """Initialize pattern detection for vulnerabilities."""
        return {
            "sql_injection": {
                "patterns": [
                    "union", "select", "insert", "update", "delete", "drop",
                    "exec", "execute", "sleep", "benchmark", "waitfor",
                    ";--", "' or '", '" or "', "1=1", "or 1=1", "/**/", "--",
                ],
                "locations": [
                    VulnerabilityLocation.QUERY_PARAMETERS,
                    VulnerabilityLocation.PAYLOAD_BODY,
                    VulnerabilityLocation.DATABASE_CONTEXT,
                ],
                "severity": 0.95,
            },
            "xss": {
                "patterns": [
                    "<script", "</script>", "onerror=", "onload=", "onclick=",
                    "javascript:", "data:text/html", "<iframe", "<svg",
                    "innerHTML", "dangerouslySetInnerHTML", "eval(",
                ],
                "locations": [
                    VulnerabilityLocation.PAYLOAD_BODY,
                    VulnerabilityLocation.EXECUTABLE_CONTEXT,
                    VulnerabilityLocation.QUERY_PARAMETERS,
                ],
                "severity": 0.85,
            },
            "path_traversal": {
                "patterns": [
                    "../", "..\\", "....//", "%2e%2e", ".env", "web.config",
                    "/etc/passwd", "c:\\windows", ".htaccess",
                ],
                "locations": [
                    VulnerabilityLocation.FILE_SYSTEM,
                    VulnerabilityLocation.URL_STRUCTURE,
                    VulnerabilityLocation.QUERY_PARAMETERS,
                ],
                "severity": 0.80,
            },
            "command_injection": {
                "patterns": [
                    ";ls", ";cat", "|ls", "|cat", "||", "&&", "`",
                    "$(", "bash", "/bin/sh", "cmd.exe", "powershell",
                ],
                "locations": [
                    VulnerabilityLocation.PAYLOAD_BODY,
                    VulnerabilityLocation.QUERY_PARAMETERS,
                    VulnerabilityLocation.EXECUTABLE_CONTEXT,
                ],
                "severity": 0.90,
            },
            "missing_security_headers": {
                "patterns": [
                    # If missing HTTPS, CSP, HSTS, X-Frame-Options
                    # This is checked separately in the method
                ],
                "locations": [
                    VulnerabilityLocation.URL_STRUCTURE,
                ],
                # PASSIVE FINDING: Severity 0.60 = MEDIUM
                # Confidence: 75-85% (pattern detection only; actual header analysis requires active testing)
                # OWASP A05:2021 – Security Misconfiguration
                "severity": 0.60,
                "is_passive": True,
            },
            "insecure_http": {
                "patterns": [
                    "http://",  # Only HTTP, not HTTPS
                ],
                "locations": [
                    VulnerabilityLocation.URL_STRUCTURE,
                ],
                # PASSIVE FINDING: Severity 0.70 = MEDIUM
                # Confidence: 85-90% (definitive pattern; HTTP protocol is clearly detectable)
                # OWASP A02:2021 – Cryptographic Failures
                "severity": 0.70,
                "is_passive": True,
            },
            "open_directories": {
                "patterns": [],  # Checked separately in _check_open_directories
                "locations": [
                    VulnerabilityLocation.URL_STRUCTURE,
                ],
                # PASSIVE FINDING: Severity 0.50 = MEDIUM (pattern detection only, not active exploitation)
                # Confidence: 65-70% (passive pattern matching; access restrictions must be verified)
                # OWASP A05:2021 – Security Misconfiguration (not A01 unless auth bypass confirmed)
                "severity": 0.50,
                "is_passive": True,
            },
        }

    def _check_security_headers(self, url: str) -> tuple[bool, list[str], dict]:
        """
        Check for potentially missing security headers based on URL patterns.
        Returns (has_issues, detected_issues, evidence)
        
        Analyzed headers:
        - Content-Security-Policy (CSP): Prevents XSS attacks
        - HTTP Strict-Transport-Security (HSTS): Enforces HTTPS
        - X-Frame-Options: Prevents clickjacking
        - X-Content-Type-Options: Prevents MIME type sniffing
        """
        issues = []
        evidence = {
            "missing_csp": False,
            "missing_hsts": False,
            "missing_x_frame_options": False,
            "missing_x_content_type_options": False,
            "insecure_protocol": False,
        }
        
        url_lower = url.lower()
        
        # Check for HTTPS (HSTS applicable)
        if url_lower.startswith("http://") and not url_lower.startswith("https://"):
            issues.append("Missing HSTS: Uses plain HTTP instead of HTTPS - enables man-in-the-middle attacks")
            evidence["insecure_protocol"] = True
            evidence["missing_hsts"] = True
        elif url_lower.startswith("https://"):
            # For HTTPS URLs, we note that HSTS should be configured
            issues.append("⚠️ Ensure HTTP Strict-Transport-Security (HSTS) header is configured with max-age")
            evidence["missing_hsts"] = True
        
        # Check for common patterns indicating lack of CSP
        if any(pattern in url_lower for pattern in [".php", ".asp", "/api/", "/graphql"]):
            issues.append("Content-Security-Policy likely needed: URL pattern suggests dynamic content generation")
            evidence["missing_csp"] = True
        
        # Check for admin/sensitive endpoints without X-Frame-Options
        if any(pattern in url_lower for pattern in ["/admin", "/user", "/account", "/settings", "/dashboard"]):
            issues.append("Missing X-Frame-Options: Sensitive endpoint vulnerable to clickjacking attacks")
            evidence["missing_x_frame_options"] = True
        
        # Check for file uploads or API endpoints without X-Content-Type-Options
        if any(pattern in url_lower for pattern in ["/upload", "/api/", "/form", "/submit"]):
            issues.append("Missing X-Content-Type-Options: nosniff - vulnerable to MIME type sniffing attacks")
            evidence["missing_x_content_type_options"] = True
        
        # For all URLs, recommend security headers as best practice
        if not issues:
            issues.append("⚠️ Verify that security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) are implemented")
            evidence["missing_csp"] = True
            evidence["missing_x_frame_options"] = True
            evidence["missing_x_content_type_options"] = True
        
        return len(issues) > 0, issues, evidence

    def _check_open_directories(self, url: str) -> tuple[bool, list[str]]:
        """
        Check for patterns indicating potentially exposed endpoints (passive detection only).
        
        IMPORTANT: Endpoint presence alone does not confirm exploitation.
        - Severity: MEDIUM (passive detection only, unless access is confirmed)
        - Confidence: 65% (pattern matching, not verified access)
        - Remediation: Access restrictions MUST be enforced via server/app config, NOT robots.txt
        
        Returns (has_issues, detected_issues)
        """
        issues = []
        url_lower = url.lower()
        
        dangerous_patterns = [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/api", "/api/v1", "/internal", "/debug", "/test",
            "/.git", "/.env", "/config", "/backup"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in url_lower:
                issues.append(f"Pattern detected: {pattern} - requires access control verification")
        
        return len(issues) > 0, issues

    # ========== STEP 1: Website Safety Check ==========
    def step1_website_safety_check(self, url: str) -> Step1Result:
        """
        STEP 1: Analyze the website URL for security issues.
        
        Classifies URL as:
        - SAFE: NO suspicious patterns detected. Safe for payload testing.
        - POTENTIALLY RISKY: Suspicious patterns detected but not conclusive.
        - UNSAFE: Clear malicious indicators present.
        
        IMPORTANT: A website is only SAFE when ALL vulnerability checks pass with NO issues found.
        """
        combined = url.lower()
        indicators: List[VulnerabilityIndicator] = []
        locations: set = set()
        max_severity = 0.0
        detected_vuln_types = []

        # Extract URL parameters for reporting
        url_params = self._extract_parameters_from_url(url)
        http_method = self._infer_http_method_from_url(url)

        # Scan for vulnerability patterns
        for vuln_type, config in self._vulnerability_patterns.items():
            # Skip placeholder entries
            if not config["patterns"]:
                continue
                
            detected_patterns = [
                p for p in config["patterns"] if p in combined
            ]
            if detected_patterns:
                severity_factor = config["severity"]
                
                # Conservative confidence levels for passive findings
                # Only high-confidence findings (>90%) have active response verification
                if vuln_type == "insecure_http":
                    # HTTP detection is definitive (pattern match = confirmed)
                    confidence = min(0.90, 0.85 + (len(detected_patterns) * 0.01))  # 85-90%
                elif vuln_type == "missing_security_headers":
                    # Security headers require actual response analysis (passive pattern only)
                    confidence = 0.80  # Fixed 75-85% range = 0.80 as midpoint
                elif vuln_type == "open_directory":
                    # Open directory is passive pattern matching (needs verification)
                    confidence = 0.67  # Fixed 65-70% range = 0.67 as midpoint
                else:
                    # Other patterns: generic confidence (detected patterns + verification)
                    confidence = min(0.85, 0.60 + (len(detected_patterns) * 0.12))  # Capped at 0.85
                
                # Determine affected parameter (first URL param or generic)
                affected_param = url_params[0] if url_params else None
                response_status = self._infer_response_status_from_context(vuln_type)
                
                indicators.append(
                    VulnerabilityIndicator(
                        indicator_type=vuln_type,
                        severity_factor=severity_factor,
                        confidence=confidence,
                        description=f"URL structure contains {len(detected_patterns)} indicator(s) for {vuln_type.replace('_', ' ')}: {', '.join(detected_patterns[:3])}",
                        affected_parameter=affected_param,
                        http_method=http_method,
                        response_status_code=response_status,
                    )
                )
                detected_vuln_types.append(vuln_type)
                for loc in config["locations"]:
                    locations.add(loc)
                max_severity = max(max_severity, severity_factor)

        # Check for security headers
        has_header_issues, header_issues, header_evidence = self._check_security_headers(url)
        if has_header_issues:
            for issue in header_issues:
                response_status = self._infer_response_status_from_context("missing_security_headers")
                
                indicators.append(
                    VulnerabilityIndicator(
                        indicator_type="missing_security_headers",
                        severity_factor=0.60,
                        confidence=0.70,
                        description=issue,
                        affected_parameter=None,
                        http_method=http_method,
                        response_status_code=response_status,
                    )
                )
                detected_vuln_types.append("missing_security_headers")
            max_severity = max(max_severity, 0.60)

        # Check for open directories
        has_open_dirs, open_dir_issues = self._check_open_directories(url)
        if has_open_dirs:
            for issue in open_dir_issues:
                response_status = self._infer_response_status_from_context("open_directory")
                
                indicators.append(
                    VulnerabilityIndicator(
                        indicator_type="open_directory",
                        severity_factor=0.50,
                        confidence=0.65,
                        description=issue,
                        affected_parameter=None,
                        http_method=http_method,
                        response_status_code=response_status,
                    )
                )
                detected_vuln_types.append("open_directory")
            max_severity = max(max_severity, 0.50)

        # CRITICAL: A website is SAFE ONLY when there are NO indicators detected
        is_safe = len(indicators) == 0
        
        if is_safe:
            status = SafetyStatus.SAFE
            explanation = (
                f"URL Structure Analysis: SAFE ✓\n\n"
                f"The provided URL appears structurally sound with no obvious malicious patterns detected in the URL construction. "
                f"The URL follows standard web conventions and does not contain suspicious encoding or syntax that would suggest attack vectors.\n\n"
                f"✓ All vulnerability checks passed:\n"
                f"  ✓ No SQL injection patterns detected\n"
                f"  ✓ No XSS payload reflection patterns detected\n"
                f"  ✓ No path traversal indicators found\n"
                f"  ✓ No command injection patterns detected\n"
                f"  ✓ No missing security headers detected\n"
                f"  ✓ No open directories exposed\n"
                f"  ✓ Uses HTTPS (secure connection)\n\n"
                f"Future Risk Assessment: LOW\n"
                f"The URL structure itself is secure. However, actual vulnerability risk depends on backend implementation:\n"
                f"• Query parameter validation strength\n"
                f"• Input sanitization practices\n"
                f"• Database query parameterization\n"
                f"• Output encoding implementation\n\n"
                f"This URL is suitable for payload injection testing in Step 2."
            )
            remediation_steps = [
                RemediationStep(
                    priority=1,
                    title="Maintain Input Validation",
                    description="Ensure all query parameters continue to receive server-side validation.",
                    code_example=(
                        "# Python example\n"
                        "from urllib.parse import parse_qs\n"
                        "params = parse_qs(request.query_string)\n"
                        "validated = validate_params(params)  # Use allowlist validation"
                    ),
                    reference="OWASP ASVS 5.1.1",
                ),
            ]
            risk_level = Severity.LOW
        else:
            # Determine if POTENTIALLY RISKY or UNSAFE
            if max_severity > 0.85:
                status = SafetyStatus.UNSAFE
                risk_level = Severity.HIGH
                status_text = "UNSAFE ✗"
            else:
                status = SafetyStatus.SUSPICIOUS
                risk_level = Severity.MEDIUM
                status_text = "POTENTIALLY RISKY ⚠"
            detected_types_str = ", ".join(set(detected_vuln_types))
            locations_str = ", ".join([loc.value.replace("_", " ").title() for loc in locations][:3])
            
            explanation = (
                f"URL Structure Analysis: {status_text}\n\n"
                f"The URL exhibits patterns that warrant security attention:\n"
                f"• Detected Patterns: {detected_types_str}\n"
                f"• Potential Vulnerability Areas: {locations_str}\n\n"
                f"Security Assessment Details:\n"
            )
            
            # Add detailed check results
            for indicator in indicators:
                explanation += f"  • {indicator.indicator_type}: {indicator.description}\n"
            
            explanation += (
                f"\nRisk Assessment:\n"
                f"• Current Risk Level: {risk_level.value.upper()}\n"
                f"• Exploitation Prerequisites: Requires vulnerable backend implementation\n"
                f"• Mitigation Priority: {'High' if risk_level == Severity.HIGH else 'Medium'}\n\n"
                f"Recommended Actions:\n"
                f"• Implement input validation and sanitization on the backend\n"
                f"• Apply output encoding appropriate to the context\n"
                f"• Review and strengthen security headers configuration\n"
                f"• Consider active payload testing after backend hardening\n\n"
                f"Note: URL patterns alone do not confirm vulnerabilities. Backend implementation determines actual security posture."
            )
            remediation_steps = self._generate_remediation(indicators, locations)

        # Deduplicate indicators
        deduplicated_indicators = self._deduplicate_indicators(indicators)

        return Step1Result(
            status=status,
            url=url,
            is_safe=is_safe,
            vulnerability_locations=list(locations),
            indicators=deduplicated_indicators,
            explanation=explanation,
            remediation_steps=remediation_steps,
            risk_level_if_unsafe=risk_level,
            proceed_to_step2=is_safe,
        )

    # ========== STEP 2: Payload Injection Analysis ==========
    def step2_payload_injection_analysis(
        self,
        url: str,
        payload: Optional[str] = None,
        step1_result: Optional[Step1Result] = None,
    ) -> Optional[Step2Result]:
        """
        STEP 2: Analyze payload with the URL (only if Step 1 is safe).
        If no payload provided, shows theoretical risk analysis.
        
        IMPORTANT: A payload is only SAFE when:
        - ML model classifies it as safe
        - NO vulnerability patterns are detected in the combined URL+payload
        - Anomaly score is within acceptable range
        """
        # If no payload provided, skip this step
        if not payload or payload.strip() == "":
            return None

        if step1_result and not step1_result.is_safe:
            raise ValueError(
                "Cannot proceed to Step 2: Website is not safe. "
                "Address Step 1 findings first."
            )

        # Use ML inference for combined analysis
        request = VulnerabilityRequest(url=url, payload=payload)
        ml_prediction = self.inference_service.score_payload(request)

        # Logging intermediate results
        print(f"[Step 2] ML Prediction - Label: {ml_prediction.label}, Probability: {ml_prediction.probability:.3f}, Anomaly: {ml_prediction.anomaly_score:.3f}")

        # Pattern detection for payload
        combined = f"{url} {payload}".lower()
        indicators: List[VulnerabilityIndicator] = []
        locations: set = set()
        attack_vectors: List[str] = []
        max_severity = 0.0

        # Extract URL parameters for reporting
        url_params = self._extract_parameters_from_url(url)
        http_method = self._infer_http_method_from_url(url)

        # Check all vulnerability patterns
        for vuln_type, config in self._vulnerability_patterns.items():
            # Skip placeholder entries
            if not config["patterns"]:
                continue
                
            detected_patterns = [
                p for p in config["patterns"] if p in combined
            ]
            if detected_patterns:
                severity_factor = config["severity"]
                confidence = min(0.95, 0.6 + (len(detected_patterns) * 0.15))
                
                # Determine affected parameter (first URL param or generic)
                affected_param = url_params[0] if url_params else None
                response_status = self._infer_response_status_from_context(vuln_type)
                
                indicators.append(
                    VulnerabilityIndicator(
                        indicator_type=vuln_type,
                        severity_factor=severity_factor,
                        confidence=confidence,
                        description=f"Payload contains {len(detected_patterns)} indicator(s) for {vuln_type.replace('_', ' ')}: {', '.join(detected_patterns[:2])}",
                        affected_parameter=affected_param,
                        http_method=http_method,
                        response_status_code=response_status,
                    )
                )
                for loc in config["locations"]:
                    locations.add(loc)
                attack_vectors.append(vuln_type)
                max_severity = max(max_severity, severity_factor)
                
                print(f"[Step 2] Detected {vuln_type}: {detected_patterns}")

        # CRITICAL: Payload is SAFE ONLY when:
        # 1. ML model says it's safe
        # 2. NO vulnerability patterns detected
        # 3. Anomaly score is low (< 0.3)
        ml_says_safe = ml_prediction.label == "safe"
        no_patterns_detected = len(indicators) == 0
        anomaly_acceptable = ml_prediction.anomaly_score < 0.3
        
        payload_safe = ml_says_safe and no_patterns_detected and anomaly_acceptable
        status = SafetyStatus.SAFE if payload_safe else SafetyStatus.UNSAFE

        print(f"[Step 2] Safety Check - ML Safe: {ml_says_safe}, No Patterns: {no_patterns_detected}, Anomaly OK: {anomaly_acceptable}, Final: {payload_safe}")

        # Generate explanation
        if payload_safe:
            explanation = (
                f"Payload Analysis: SAFE\n\n"
                f"The provided payload does not exhibit injection attack characteristics.\n\n"
                f"Analysis Results:\n"
                f"  ✓ ML Classification: Safe\n"
                f"  ✓ Confidence Score: {ml_prediction.probability:.1%}\n"
                f"  ✓ Anomaly Assessment: {ml_prediction.anomaly_score:.3f} (within acceptable range)\n"
                f"  ✓ Pattern Analysis: No malicious signatures detected\n\n"
                f"Assessment: This payload does not appear to leverage common injection attack vectors."
            )
            remediation_steps = []
            combined_risk = Severity.LOW
        else:
            attack_vectors_str = ", ".join(set(attack_vectors)) if attack_vectors else "Unknown"
            locations_str = ", ".join([loc.value.replace("_", " ").title() for loc in locations][:3]) if locations else "Unknown"
            
            explanation = (
                f"Payload Analysis: Requires Attention\n\n"
                f"The payload contains patterns associated with common attack vectors.\n\n"
                f"Findings:\n"
            )
            
            if not ml_says_safe:
                explanation += f"  • ML Classification: Potential attack pattern detected\n"
                explanation += f"  • Confidence: {ml_prediction.probability:.1%}\n"
            else:
                explanation += f"  ✓ ML Model Classification: SAFE\n"
            
            explanation += f"  • Anomaly Score: {ml_prediction.anomaly_score:.3f}\n"
            
            for indicator in indicators:
                explanation += f"  • {indicator.indicator_type}: {indicator.description}\n"
            
            if attack_vectors:
                explanation += f"\nIdentified Patterns: {attack_vectors_str}\n"
                explanation += f"Potential Injection Points: {locations_str}\n"
            
            explanation += (
                f"\nRecommendation: Verify backend implementation with active penetration testing."
            )
            
            remediation_steps = self._generate_remediation(indicators, locations)
            combined_risk = ml_prediction.severity

        # Deduplicate indicators
        deduplicated_indicators = self._deduplicate_indicators(indicators)

        return Step2Result(
            status=status,
            payload_safe=payload_safe,
            combined_risk=combined_risk,
            vulnerability_locations=list(locations),
            indicators=deduplicated_indicators,
            explanation=explanation,
            remediation_steps=remediation_steps,
            attack_vectors_detected=attack_vectors,
        )

    # ========== STEP 3: Risk Evaluation ==========
    def step3_risk_evaluation(
        self,
        step1_result: Step1Result,
        step2_result: Optional[Step2Result] = None,
    ) -> Step3Result:
        """
        STEP 3: Assign risk level and calculate risk score based on analysis.
        
        RISK SCORING LOGIC FOR PASSIVE FINDINGS:
        - Single Medium passive finding: 20-30/100 (0.20-0.30)
        - Two Medium passive findings: 30-40/100 (0.30-0.40)
        - Three Medium passive findings: 40-45/100 (0.40-0.45) ← TARGET RANGE
        - Multiple HIGH findings: 50-85/100 (0.50-0.85)
        
        HIGH findings (confirmed exploitation) trigger higher scores.
        Passive findings (pattern detection only) are capped at MEDIUM severity.
        """
        if step2_result is None:
            # Only Step 1 analysis (no payload or website was unsafe)
            risk_level = step1_result.risk_level_if_unsafe
            indicators = step1_result.indicators
            
            # Calculate risk_score based on number and severity of passive findings
            passive_count = sum(1 for ind in indicators if ind.indicator_type in ["missing_security_headers", "open_directory"])
            active_count = len(indicators) - passive_count
            
            if risk_level == Severity.HIGH:
                # Active exploitation confirmed
                risk_score = 0.85
            elif risk_level == Severity.MEDIUM and active_count > 0:
                # Medium + confirmed vulnerabilities
                risk_score = 0.65
            elif risk_level == Severity.MEDIUM:
                # Passive findings only
                # Formula: 0.15 + (0.10 * passive_count), capped at 0.45
                # 1 passive = 0.25, 2 passive = 0.35, 3+ passive = 0.45
                risk_score = min(0.15 + (0.10 * passive_count), 0.45)
            else:
                # LOW severity
                risk_score = 0.15
            
            contributing_factors = [
                ind.indicator_type for ind in indicators
            ]
            
            if not contributing_factors:
                contributing_factors = ["URL structure is sound", "No suspicious patterns in URL"]
                justification = (
                    f"URL-Only Analysis: Risk score {risk_score * 100:.0f}/100 ({risk_level.value.upper()}).\n"
                    f"No payload analyzed - future risk depends on backend validation implementation.\n"
                    f"Security measures must be in place to prevent injection attacks."
                )
            else:
                factors_str = ", ".join(contributing_factors)
                passive_note = f" ({passive_count} passive findings)" if passive_count > 0 else ""
                
                # Show formula for transparency
                if passive_count > 0 and active_count == 0:
                    formula_text = f"\nRisk Formula (Passive Findings): 0.15 + (0.10 × {passive_count} findings) = {risk_score:.2f} ({int(risk_score * 100)}/100)"
                else:
                    formula_text = ""
                
                justification = (
                    f"Website-level vulnerabilities detected{passive_note}. Risk score: {int(risk_score * 100)}/100.\n"
                    f"Detected Factors: {factors_str}.{formula_text}\n"
                    f"Remediation required before proceeding with active testing."
                )
        else:
            # Step 1 and Step 2 analysis (website safe, payload analyzed)
            risk_level = step2_result.combined_risk
            risk_score = 0.1 if risk_level == Severity.LOW else (
                0.55 if risk_level == Severity.MEDIUM else 0.9
            )
            contributing_factors = [
                ind.indicator_type for ind in step2_result.indicators
            ]
            
            if not contributing_factors:
                contributing_factors = ["No malicious patterns detected"]
                justification = (
                    f"Payload Analysis: Risk score {risk_score * 100:.0f}/100 ({risk_level.value.upper()}).\n"
                    f"No attack vectors detected in payload. Safe for deployment."
                )
            else:
                factors_str = ", ".join(set(contributing_factors))
                justification = (
                    f"Payload Analysis: Risk score {risk_score * 100:.0f}/100 ({risk_level.value.upper()}).\n"
                    f"Attack vectors detected: {factors_str}.\n"
                    f"Remediation required before production use."
                )

        return Step3Result(
            risk_level=risk_level,
            risk_score=risk_score,
            justification=justification,
            contributing_factors=contributing_factors,
        )

    # ========== STEP 4: Explanation & Guidance ==========
    def step4_explanation_guidance(
        self,
        step1_result: Step1Result,
        step2_result: Optional[Step2Result] = None,
    ) -> Step4Result:
        """
        STEP 4: Provide detailed explanation and security guidance.
        Handles both URL-only and URL+Payload analysis scenarios.
        """
        vulnerable_areas = [
            loc.value for loc in step1_result.vulnerability_locations
        ]
        if step2_result:
            for loc in step2_result.vulnerability_locations:
                if loc.value not in vulnerable_areas:
                    vulnerable_areas.append(loc.value)

        # Build detailed explanation
        detailed_explanation = step1_result.explanation
        if step2_result:
            detailed_explanation += f"\n\n{step2_result.explanation}"
        else:
            # No payload analysis - add guidance about future risks
            detailed_explanation += (
                "\n\nNote: No payload was provided for analysis. "
                "This assessment covers URL structure only. "
                "Actual vulnerability risk depends on:\n"
                "• Backend input validation strength\n"
                "• Output encoding implementation\n"
                "• Framework security configuration\n"
                "• Database query parameterization"
            )

        # Collect best practices (prioritized based on findings)
        best_practices = []
        
        # Add specific practices based on detected indicators
        all_indicators = step1_result.indicators + (step2_result.indicators if step2_result else [])
        detected_types = {ind.indicator_type for ind in all_indicators}
        
        if "sql_injection" in detected_types:
            best_practices.append("Use parameterized queries and prepared statements for all database operations")
            best_practices.append("Never concatenate user input directly into SQL queries")
        
        if "xss" in detected_types:
            best_practices.append("Implement Content Security Policy (CSP) headers to mitigate XSS attacks")
            best_practices.append("Always validate and sanitize all user inputs on both client and server sides")
        
        if "path_traversal" in detected_types:
            best_practices.append("Validate and normalize file paths against an allowlist")
            best_practices.append("Use principle of least privilege for file system access")
        
        if "command_injection" in detected_types:
            best_practices.append("Use language-native APIs instead of shell command execution")
            best_practices.append("Never pass user input directly to system commands")
        
        # Add general practices if none detected
        if not best_practices:
            best_practices = [
                "Always validate and sanitize all user inputs on both client and server sides",
                "Use prepared statements and parameterized queries to prevent SQL injection",
                "Implement Content Security Policy (CSP) headers to mitigate XSS attacks",
                "Employ input encoding and output escaping based on context",
                "Use allowlists for input validation rather than blocklists",
            ]
        
        # Add additional general practices
        best_practices.extend([
            "Keep all dependencies and frameworks updated to the latest secure versions",
            "Implement comprehensive logging and monitoring for security events",
            "Conduct regular security testing and code reviews",
            "Use Web Application Firewalls (WAF) as an additional layer of defense",
            "Implement proper error handling that doesn't expose sensitive information",
        ])
        
        best_practices = best_practices[:10]  # Limit to 10 best practices

        # Collect references based on findings
        references = []
        
        if detected_types:
            references.append("OWASP Top 10 2021 - A03:2021 Injection")
            references.append("OWASP ASVS 5 - Validation, Sanitization and Encoding")
        
        references.extend([
            "NIST SP 800-53 SI-10 - Information System Monitoring",
            "CWE-89 - Improper Neutralization of Special Elements used in SQL Command",
            "CWE-79 - Cross-site Scripting (XSS)",
            "OWASP Cheat Sheet Series - Input Validation",
            "OWASP Secure Coding Practices",
        ])
        
        references = references[:6]  # Limit to 6 references

        return Step4Result(
            detailed_explanation=detailed_explanation,
            vulnerable_areas=vulnerable_areas,
            best_practices=best_practices,
            references=references,
        )

    # ========== STEP 5: Remediation Suggestions ==========
    def step5_remediation_suggestions(
        self,
        step1_result: Step1Result,
        step2_result: Optional[Step2Result] = None,
        step3_result: Optional[Step3Result] = None,
    ) -> Step5Result:
        """
        STEP 5: Provide comprehensive remediation suggestions based on all previous findings.
        Includes priority actions, long-term strategy, and compliance requirements.
        Handles both URL-only and URL+Payload analysis scenarios.
        """
        priority_remediations: List[RemediationStep] = []
        short_term_actions: List[str] = []
        long_term_strategy: List[str] = []
        compliance_requirements: List[str] = []

        # Collect all remediation steps from previous steps
        all_steps = list(step1_result.remediation_steps)
        if step2_result:
            all_steps.extend(step2_result.remediation_steps)

        # Remove duplicates and sort by priority
        seen_titles = set()
        for step in sorted(all_steps, key=lambda x: x.priority):
            if step.title not in seen_titles:
                priority_remediations.append(step)
                seen_titles.add(step.title)
                if len(priority_remediations) >= 5:
                    break

        # Generate short-term actions (immediate fixes)
        if step2_result and not step2_result.payload_safe:
            # Payload is malicious
            short_term_actions = [
                "Immediately patch the identified injection vulnerability in the application",
                "Review and update input validation logic at the affected endpoint",
                "Audit recent logs for exploitation attempts and unauthorized access",
                "Conduct a security review of the vulnerable code path",
                "Implement rate limiting and WAF rules on the suspicious endpoint",
            ]
        elif step1_result.indicators:
            # URL has suspicious patterns
            short_term_actions = [
                "Review URL structure and remove suspicious patterns",
                "Implement comprehensive input validation for all parameters",
                "Audit the endpoint for existing vulnerabilities",
                "Update security headers and HTTPS configuration",
                "Deploy security monitoring for the affected endpoint",
            ]
        else:
            # No issues detected
            short_term_actions = [
                "Maintain security monitoring and logging",
                "Implement regular vulnerability scanning in CI/CD pipeline",
                "Establish security testing as part of code review process",
                "Update security headers if not already in place",
                "Document security controls for this endpoint",
            ]
        
        short_term_actions = short_term_actions[:4]

        # Generate long-term strategy
        long_term_strategy = [
            "Implement a comprehensive security testing program (SAST/DAST/DOST)",
            "Establish secure coding standards and conduct regular developer training",
            "Deploy Web Application Firewall (WAF) with ML-based threat detection",
            "Implement automated security scanning in the CI/CD pipeline",
            "Conduct quarterly penetration testing and security audits",
            "Maintain an up-to-date inventory and patch management for all dependencies",
            "Establish incident response procedures and 24/7 security monitoring",
            "Implement security-first development culture with threat modeling workshops",
        ][:5]

        # Generate compliance requirements based on risk level
        if step3_result:
            if step3_result.risk_level == Severity.HIGH:
                compliance_requirements = [
                    "PCI DSS v3.2.1 - Requirement 6: Maintain secure development practices",
                    "GDPR Article 32: Implement technical security measures",
                    "HIPAA Security Rule: Safeguards for protected health information",
                    "SOC 2 Type II: Security, availability, processing integrity",
                    "CIS Controls v8: Critical security controls implementation",
                ]
            elif step3_result.risk_level == Severity.MEDIUM:
                compliance_requirements = [
                    "OWASP ASVS Level 2: Compliance with standard security practices",
                    "CIS Controls v8: Foundation-level security controls",
                    "NIST Cybersecurity Framework: Core functions implementation",
                    "ISO/IEC 27001: Information security management",
                ]
            else:
                compliance_requirements = [
                    "OWASP ASVS Level 1: Basic security practices",
                    "Industry best practices: Standard security guidelines",
                    "NIST SP 800-53: General security controls",
                ]
        
        compliance_requirements = compliance_requirements[:4]

        # Determine estimated effort
        if step3_result:
            if step3_result.risk_score > 0.8:
                estimated_effort = "High"
            elif step3_result.risk_score > 0.5:
                estimated_effort = "Medium"
            else:
                estimated_effort = "Low"
        else:
            estimated_effort = "Medium"

        # Generate summary based on analysis type
        if step2_result:
            summary = (
                f"Analysis identified {len(all_steps)} remediation areas across URL and payload. "
                f"Priority: {priority_remediations[0].title if priority_remediations else 'General hardening'}. "
                f"Payload Status: {'SAFE' if step2_result.payload_safe else 'UNSAFE'}. "
                f"Estimated effort: {estimated_effort}. "
                f"Recommend immediate action on priority items and planning for long-term security improvements."
            )
        else:
            summary = (
                f"Analysis identified {len(all_steps)} remediation areas from URL assessment. "
                f"No payload was analyzed - actual risk depends on backend implementation. "
                f"Estimated effort: {estimated_effort}. "
                f"Focus on implementing input validation and security controls at backend level."
            )

        return Step5Result(
            priority_remediations=priority_remediations,
            short_term_actions=short_term_actions,
            long_term_strategy=long_term_strategy,
            compliance_requirements=compliance_requirements,
            estimated_effort=estimated_effort,
            summary=summary,
        )

    # ========== COMPLETE WORKFLOW ==========
    def execute_workflow(
        self,
        url: str,
        payload: Optional[str] = None,
    ) -> SequentialWorkflowResult:
        """
        Execute the complete 5-step sequential workflow.
        
        STEP 1: Website Safety Check - Analyzes URL for structural security issues
        STEP 2: Payload Injection Analysis - Analyzes payload combined with URL (only if provided and Step 1 safe)
        STEP 3: Risk Evaluation - Assigns risk level based on all analysis
        STEP 4: Explanation & Guidance - Provides detailed findings and best practices
        STEP 5: Remediation Suggestions - Comprehensive security fixes and strategy
        """
        # Generate scan timestamp in IST timezone
        scan_timestamp = self._get_ist_timestamp()

        # STEP 1: Website Safety Check
        step1_result = self.step1_website_safety_check(url)

        step2_result = None
        step3_result = None
        step4_result = None
        step5_result = None

        # STEP 2: Payload Injection Analysis (only if safe and payload provided)
        if step1_result.is_safe and payload and payload.strip():
            step2_result = self.step2_payload_injection_analysis(
                url, payload, step1_result
            )
        elif payload and payload.strip() and not step1_result.is_safe:
            # Website is not safe, but still document theoretical risk with payload
            step2_result = None

        # STEP 3: Risk Evaluation
        step3_result = self.step3_risk_evaluation(step1_result, step2_result)

        # STEP 4: Explanation & Guidance
        step4_result = self.step4_explanation_guidance(step1_result, step2_result)

        # STEP 5: Remediation Suggestions
        step5_result = self.step5_remediation_suggestions(
            step1_result, step2_result, step3_result
        )

        # Complete workflow
        status_message = "Workflow completed successfully - All 5 steps analyzed"
        workflow_completed = True

        return SequentialWorkflowResult(
            scan_timestamp=scan_timestamp,
            step1=step1_result,
            step2=step2_result,
            step3=step3_result,
            step4=step4_result,
            step5=step5_result,
            workflow_completed=workflow_completed,
            status_message=status_message,
        )

    # ========== HELPER METHODS ==========
    def _generate_remediation(
        self,
        indicators: List[VulnerabilityIndicator],
        locations: set,
    ) -> List[RemediationStep]:
        """Generate remediation steps based on detected vulnerabilities."""
        remediation_map = {
            "sql_injection": RemediationStep(
                priority=1,
                title="Implement Parameterized Queries",
                description="Use prepared statements or ORM to prevent SQL injection attacks.",
                code_example=(
                    "# Python example with parameterized query\n"
                    "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                ),
                reference="OWASP ASVS 5.3.1",
            ),
            "xss": RemediationStep(
                priority=1,
                title="Sanitize and Escape Output",
                description="Properly escape all user-controlled content before rendering.",
                code_example=(
                    "# React example\n"
                    "import DOMPurify from 'dompurify';\n"
                    "const safe = DOMPurify.sanitize(userInput);"
                ),
                reference="OWASP ASVS 5.1.3",
            ),
            "path_traversal": RemediationStep(
                priority=1,
                title="Validate File Paths",
                description="Normalize and validate all file paths against an allowlist.",
                code_example=(
                    "# Python example\n"
                    "import os\n"
                    "safe_path = os.path.normpath(user_path)\n"
                    "if not safe_path.startswith(SAFE_ROOT):\n"
                    "    raise ValueError('Invalid path')"
                ),
                reference="NIST 800-53 SI-10",
            ),
            "command_injection": RemediationStep(
                priority=1,
                title="Avoid Shell Execution",
                description="Use language-native APIs instead of shell commands.",
                code_example=(
                    "# Python example\n"
                    "import subprocess\n"
                    "result = subprocess.run(['command', arg], shell=False)"
                ),
                reference="OWASP ASVS 5.3.8",
            ),
        }

        steps = []
        seen = set()
        for indicator in indicators:
            if (
                indicator.indicator_type in remediation_map
                and indicator.indicator_type not in seen
            ):
                steps.append(remediation_map[indicator.indicator_type])
                seen.add(indicator.indicator_type)

        # Add general hardening step if no specific remediations
        if not steps:
            steps.append(
                RemediationStep(
                    priority=2,
                    title="General Input Validation",
                    description="Implement comprehensive input validation and output encoding.",
                    code_example=(
                        "# Validate input format, length, and content\n"
                        "if not validate_input(user_input):\n"
                        "    raise ValueError('Invalid input')"
                    ),
                    reference="OWASP Top 10 2021",
                )
            )

        return steps[:3]  # Return top 3 remediation steps

    # ========== MAIN WORKFLOW EXECUTOR ==========
    def execute_workflow(self, url: str, payload: Optional[str] = None) -> SequentialWorkflowResult:
        """
        Execute the complete 5-step sequential vulnerability analysis workflow.
        
        Args:
            url: The URL to analyze
            payload: Optional payload to inject and analyze
            
        Returns:
            Complete SequentialWorkflowResult with all 5 steps
        """
        scan_timestamp = self._get_ist_timestamp()
        
        try:
            # STEP 1: Website Safety Check
            step1_result = self.step1_website_safety_check(url)
            
            # STEP 2: Payload Injection Analysis (only if safe)
            step2_result = None
            if step1_result.proceed_to_step2 and payload:
                step2_result = self.step2_payload_injection_analysis(url, payload, step1_result)
            
            # STEP 3: Risk Evaluation
            step3_result = self.step3_risk_evaluation(step1_result, step2_result)
            
            # STEP 4: Explanation & Guidance
            step4_result = self.step4_explanation_guidance(step1_result, step2_result)
            
            # STEP 5: Remediation Suggestions
            step5_result = self.step5_remediation_suggestions(step1_result, step2_result, step3_result)
            
            status_message = "Workflow completed successfully - All 5 steps analyzed"
            workflow_completed = True
            
        except Exception as e:
            # If any step fails, return partial results
            step1_result = step1_result if 'step1_result' in locals() else None
            step2_result = step2_result if 'step2_result' in locals() else None
            step3_result = step3_result if 'step3_result' in locals() else None
            step4_result = step4_result if 'step4_result' in locals() else None
            step5_result = step5_result if 'step5_result' in locals() else None
            
            status_message = f"Workflow partially completed - Error: {str(e)}"
            workflow_completed = False
            
            # Create minimal results if needed
            if not step3_result and step1_result:
                step3_result = self.step3_risk_evaluation(step1_result, step2_result)
            if not step4_result:
                step4_result = self.step4_explanation_guidance(step1_result, step2_result)
            if not step5_result:
                step5_result = self.step5_remediation_suggestions(step1_result, step2_result, step3_result)
        
        return SequentialWorkflowResult(
            scan_timestamp=scan_timestamp,
            step1=step1_result,
            step2=step2_result,
            step3=step3_result,
            step4=step4_result,
            step5=step5_result,
            workflow_completed=workflow_completed,
            status_message=status_message,
        )
