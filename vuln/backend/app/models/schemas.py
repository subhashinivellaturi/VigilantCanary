from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict


class Severity(Enum):
    """OWASP standard severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityType(Enum):
    """Independent vulnerability types reported separately."""
    INSECURE_HTTP = "insecure_http"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    OPEN_DIRECTORY = "open_directory"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    CSRF = "csrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    UNKNOWN = "unknown"


class PayloadMetadata(BaseModel):
    framework: Optional[str] = Field(default=None, examples=["django", "nextjs"])
    code_language: Optional[str] = Field(default=None, examples=["python", "javascript"])
    notes: Optional[str] = Field(default=None)


class VulnerabilityRequest(BaseModel):
    url: str = Field(..., description="Full URL or route being analyzed.")
    payload: str = Field(..., description="Body, parameters, or snippet to scan.")
    metadata: PayloadMetadata | None = None


class FeatureImportance(BaseModel):
    feature: str
    contribution: float


class FixSuggestion(BaseModel):
    title: str
    description: str
    reference: str


class VulnerabilityResponse(BaseModel):
    timestamp: datetime
    label: str
    probability: float
    severity: Severity
    anomaly_score: float
    feature_insights: List[FeatureImportance]
    suggestions: List[FixSuggestion]
    cvss_score: float | None = None


class MetricSnapshot(BaseModel):
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    status: str
    model_version: str
    dataset_size: int
    metrics: MetricSnapshot | None = None


# Remediation schemas
class RemediationRequest(BaseModel):
    code_snippet: str = Field(..., description="Code to analyze for vulnerabilities.")
    vulnerability_type: str = Field(
        ...,
        description="Type of vulnerability: sql_injection, path_traversal, xss, command_injection"
    )
    language: str = Field(..., description="Programming language: python, javascript, etc.")
    url: Optional[str] = Field(default=None, description="URL context where vulnerability was found.")


class RemediationResponse(BaseModel):
    vulnerability_type: str
    vulnerable_lines: List[int]
    explanation: str
    secure_code: str
    why_it_works: str
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID")
    cve_references: Optional[List[str]] = Field(default=None, description="Related CVE references")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 category")


class OwaspTop10Response(BaseModel):
    """OWASP Top 10 information and mappings."""
    category: str
    title: str
    description: str
    vulnerabilities: List[str]
    prevention_measures: List[str]
    cwe_mappings: List[str]


# Attack classification schemas
class AttackClassificationRequest(BaseModel):
    url: str = Field(..., description="URL being analyzed.")
    payload: str = Field(..., description="Payload or request body.")
    context: Optional[str] = Field(default=None, description="Additional context.")


class AttackClassificationResponse(BaseModel):
    attack_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    risk_indicators: List[str]


# Chatbot/Prompts schemas
class PromptsResponse(BaseModel):
    chatbot: str = Field(..., description="System prompt for developer chatbot.")
    remediation: str = Field(..., description="System prompt for code remediation.")
    classification: str = Field(..., description="System prompt for attack classification.")


# Sequential Workflow schemas
class SequentialWorkflowRequest(BaseModel):
    """Request for sequential vulnerability analysis workflow."""
    url: str = Field(..., description="Website URL to analyze")
    payload: Optional[str] = Field(default=None, description="Payload to inject (optional)")


class VulnerabilityIndicatorResponse(BaseModel):
    """A detected vulnerability indicator."""
    indicator_type: str
    severity_factor: float
    confidence: float
    description: str
    affected_parameter: Optional[str] = None
    http_method: str = "GET"
    response_status_code: Optional[int] = None


class RemediationStepResponse(BaseModel):
    """A recommended security fix."""
    priority: int
    title: str
    description: str
    code_example: str
    reference: str


class Step1ResponseModel(BaseModel):
    """Result of Website Safety Check (Step 1)."""
    status: str
    url: str
    is_safe: bool
    vulnerability_locations: List[str]
    indicators: List[VulnerabilityIndicatorResponse]
    explanation: str
    remediation_steps: List[RemediationStepResponse]
    risk_level_if_unsafe: str
    proceed_to_step2: bool


class Step2ResponseModel(BaseModel):
    """Result of Payload Injection Analysis (Step 2)."""
    status: str
    payload_safe: bool
    combined_risk: str
    vulnerability_locations: List[str]
    indicators: List[VulnerabilityIndicatorResponse]
    explanation: str
    remediation_steps: List[RemediationStepResponse]
    attack_vectors_detected: List[str]


class Step3ResponseModel(BaseModel):
    """Result of Risk Evaluation (Step 3)."""
    risk_level: str
    risk_score: float
    justification: str
    contributing_factors: List[str]


class Step4ResponseModel(BaseModel):
    """Result of Explanation & Guidance (Step 4)."""
    detailed_explanation: str
    vulnerable_areas: List[str]
    best_practices: List[str]
    references: List[str]


class Step5ResponseModel(BaseModel):
    """Result of Remediation Suggestions (Step 5)."""
    priority_remediations: List[RemediationStepResponse]
    short_term_actions: List[str]
    long_term_strategy: List[str]
    compliance_requirements: List[str]
    estimated_effort: str
    summary: str


class SequentialWorkflowResponse(BaseModel):
    """Complete sequential workflow result."""
    scan_timestamp: str  # IST timezone ISO format timestamp
    step1: Step1ResponseModel
    step2: Optional[Step2ResponseModel] = None
    step3: Step3ResponseModel
    step4: Step4ResponseModel
    step5: Step5ResponseModel
    workflow_completed: bool
    status_message: str
    disclaimer: str = "⚠️ Automated scanning results may require manual verification by security professionals for production systems."


# ============================================================================
# PRODUCTION-GRADE INDEPENDENT VULNERABILITY REPORTING
# ============================================================================

class IndependentFinding(BaseModel):
    """A single, independent vulnerability finding - OWASP aligned."""
    finding_id: str = Field(..., description="Unique identifier (e.g., f1, f2, f3)")
    vulnerability_type: str = Field(..., description="Type: insecure_http, missing_security_headers, xss, sql_injection, csrf, path_traversal, command_injection, open_directory")
    severity: str = Field(..., description="OWASP severity: low, medium, high, critical")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS-style score (0-10)")
    confidence: float = Field(..., ge=0.0, le=100.0, description="Confidence percentage (0-100)")
    description: str = Field(..., description="Clear description of the vulnerability")
    affected_url: Optional[str] = Field(default=None, description="Specific URL where vulnerability was detected")
    affected_parameter: Optional[str] = Field(default=None, description="Parameter name if applicable")
    http_method: str = Field(default="GET", description="HTTP method where vulnerability detected")
    payload_used: Optional[str] = Field(default=None, description="Payload that triggered this finding (if active testing)")
    payload_result: Optional[str] = Field(default=None, description="Result from payload execution (if active testing)")
    remediation_steps: List[str] = Field(default_factory=list, description="Actionable remediation steps")
    owasp_reference: Optional[str] = Field(default=None, description="OWASP Top 10 or other standard reference")
    is_duplicate: bool = Field(default=False, description="True if this is a duplicate of another finding")
    duplicate_of: Optional[str] = Field(default=None, description="ID of original finding if duplicate")


class ScanMode(Enum):
    """Track scan type for UI/reporting."""
    PASSIVE_ONLY = "passive_only"
    ACTIVE_WITH_PAYLOAD = "active_with_payload"


class ExecutiveSummary(BaseModel):
    """Executive-level summary for PDF export and reporting."""
    scan_timestamp: str
    scanned_url: str
    scan_mode: str = Field(..., description="'passive_only' or 'active_with_payload'")
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_status: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'UNSAFE'")
    risk_score_0_to_100: int = Field(..., description="Overall risk score 0-100")
    executive_summary_text: str = Field(..., description="2-3 sentence summary suitable for C-level")
    remediation_priority: str = Field(..., description="'Immediate', 'High', 'Medium', 'Can be deferred'")


class ProductionScanResponse(BaseModel):
    """Complete, production-grade scan response with independent findings."""
    scan_timestamp: str
    scanned_url: str
    scan_mode: str = Field(default="passive_only", description="'passive_only' or 'active_with_payload'")
    findings: List[IndependentFinding] = Field(..., description="List of independent vulnerability findings")
    finding_counts: dict = Field(..., description="Counts by type: {'xss': 2, 'sql_injection': 1, ...}")
    severity_breakdown: dict = Field(..., description="Counts by severity: {'critical': 1, 'high': 2, 'medium': 3, 'low': 1}")
    executive_summary: ExecutiveSummary
    disclaimer: str = "⚠️ Automated scanning results may require manual verification by security professionals for production systems."
    notes: Optional[str] = Field(default=None, description="Additional notes or observations")


# ============================================================================
# FEEDBACK AND SELF-EVOLVING SYSTEM SCHEMAS
# ============================================================================

class FeedbackType(Enum):
    """Types of user feedback for model improvement."""
    CORRECT_PREDICTION = "correct_prediction"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    MISCLASSIFIED_SEVERITY = "misclassified_severity"
    IMPROVEMENT_SUGGESTION = "improvement_suggestion"


class FeedbackRequest(BaseModel):
    """User feedback for continuous model improvement."""
    url: str = Field(..., description="URL that was analyzed")
    payload: str = Field(..., description="Payload that was analyzed")
    predicted_label: str = Field(..., description="What the system predicted")
    predicted_probability: float = Field(..., description="Predicted probability score")
    actual_label: str = Field(..., description="What the user believes is correct")
    feedback_type: FeedbackType = Field(..., description="Type of feedback")
    user_explanation: Optional[str] = Field(default=None, description="User's explanation of why this feedback is given")
    severity_override: Optional[str] = Field(default=None, description="Correct severity if misclassified")
    additional_context: Optional[str] = Field(default=None, description="Any additional context")


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""
    feedback_id: str = Field(..., description="Unique ID for this feedback")
    status: str = Field(..., description="Status of feedback submission")
    message: str = Field(..., description="Confirmation message")
    will_retrain: bool = Field(..., description="Whether this feedback will trigger model retraining")
    current_accuracy: Optional[float] = Field(default=None, description="Current model accuracy after feedback")


# Port Scan schemas
class PortScanRequest(BaseModel):
    """Request to scan open ports on a host."""
    target: str = Field(..., description="Target IP address or hostname", examples=["192.168.1.1", "example.com"])
    ports: Optional[List[int]] = Field(default=None, description="Specific ports to scan (defaults to common ports)")


class OpenPort(BaseModel):
    """Representation of an open port found during scan."""
    port: int = Field(..., description="Port number", examples=[80, 443, 22])
    service: str = Field(..., description="Service name/type", examples=["http", "https", "ssh"])
    state: str = Field(..., description="Port state: open, closed, filtered", examples=["open"])


class PortScanResponse(BaseModel):
    """Response from port scanning."""
    scan_id: str = Field(..., description="Unique scan identifier")
    target_host: str = Field(..., description="Target of the scan")
    scan_timestamp: str = Field(..., description="ISO 8601 timestamp when scan was performed")
    scanned_ports: List[int] = Field(..., description="List of all ports that were scanned")
    open_ports: List[OpenPort] = Field(..., description="Open ports found")
    total_scanned: int = Field(..., description="Total number of ports scanned")
    open_count: int = Field(..., description="Number of open ports found")
    status: str = Field(default="completed", description="Scan status: completed, running, failed")
    severity: str = Field(default="low", description="Risk severity (all open ports are Low severity)")
    message: str = Field(..., description="Summary message")
    disclaimer: str = Field(
        default="⚠️ Port scanning is for authorized targets only. Unauthorized scanning may be illegal.",
        description="Legal disclaimer"
    )

