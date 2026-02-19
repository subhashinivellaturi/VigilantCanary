"""
Context-aware vulnerability detection to reduce false positives.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class ContextType(Enum):
    """Types of context that can affect vulnerability detection."""
    BUSINESS_LOGIC = "business_logic"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    SANITIZATION = "sanitization"


@dataclass
class ContextIndicator:
    """Represents a context indicator that affects vulnerability assessment."""
    type: ContextType
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: List[str]


class ContextAwareDetector:
    """
    Analyzes code and request context to reduce false positives in vulnerability detection.
    """

    # Patterns that indicate proper security measures
    SECURITY_PATTERNS = {
        "authentication": [
            r"authenticate|login|session|token|jwt|oauth",
            r"password.*hash|bcrypt|scrypt|argon2",
            r"is_authenticated|is_logged_in|check_auth",
        ],
        "authorization": [
            r"authorize|permission|role|access_control",
            r"can_.*|has_.*_permission|check_role",
            r"@requires_auth|@login_required|@permission",
        ],
        "input_validation": [
            r"validate|clean|sanitize|escape|strip_tags",
            r"re\.match|re\.search|pattern\.match",
            r"htmlspecialchars|escape_html|bleach\.clean",
            r"validate_email|validate_url|is_valid",
        ],
        "output_encoding": [
            r"escape|encode|html\.escape|htmlspecialchars",
            r"json\.dumps|jsonify|safe_join",
            r"mark_safe|autoescape.*true",
        ],
        "sanitization": [
            r"sanitize|sanitizer|clean_input|filter_var",
            r"DOMPurify\.sanitize|xss\.clean|strip_tags",
            r"sqlalchemy\.text|prepared.*statement",
        ],
    }

    # Business logic patterns that might look like vulnerabilities
    BUSINESS_LOGIC_PATTERNS = [
        r"order.*by.*id|sort.*by.*date|filter.*status",
        r"group.*by.*category|limit.*offset|page.*size",
        r"search.*query|fulltext.*search|elasticsearch",
        r"cache.*key|redis.*get|memcache",
        r"config.*value|setting.*get|environment",
        r"log.*entry|audit.*trail|activity.*log",
        r"template.*render|view.*render|component",
    ]

    @classmethod
    def analyze_context(
        cls,
        code_snippet: str,
        url: str,
        payload: str,
        vulnerability_type: str
    ) -> Dict[str, float]:
        """
        Analyze context to determine if a potential vulnerability is actually secure.

        Returns a dictionary of context factors that reduce confidence in the vulnerability.
        Higher values indicate stronger evidence that the detection might be a false positive.
        """
        context_factors = {}

        # Check for authentication/authorization context
        auth_context = cls._check_authentication_context(code_snippet, url)
        if auth_context > 0:
            context_factors["authentication_present"] = auth_context

        # Check for input validation
        validation_context = cls._check_input_validation_context(code_snippet, payload)
        if validation_context > 0:
            context_factors["input_validation_present"] = validation_context

        # Check for output encoding/sanitization
        if vulnerability_type.lower() == "xss":
            encoding_context = cls._check_output_encoding_context(code_snippet)
            if encoding_context > 0:
                context_factors["output_encoding_present"] = encoding_context

        # Check for SQL security measures
        if vulnerability_type.lower() == "sql_injection":
            sql_context = cls._check_sql_security_context(code_snippet)
            if sql_context > 0:
                context_factors["sql_security_present"] = sql_context

        # Check for business logic that might look suspicious
        business_context = cls._check_business_logic_context(code_snippet, payload, url)
        if business_context > 0:
            context_factors["business_logic_context"] = business_context

        # Check for command injection security
        if vulnerability_type.lower() == "command_injection":
            command_context = cls._check_command_security_context(code_snippet)
            if command_context > 0:
                context_factors["command_security_present"] = command_context

        return context_factors

    @classmethod
    def _check_authentication_context(cls, code_snippet: str, url: str) -> float:
        """Check if authentication/authorization context is present."""
        score = 0.0

        # Check URL for auth-related endpoints
        auth_urls = ["login", "auth", "session", "token", "admin", "dashboard"]
        if any(auth_term in url.lower() for auth_term in auth_urls):
            score += 0.3

        # Check code for authentication patterns
        for pattern_list in [cls.SECURITY_PATTERNS["authentication"], cls.SECURITY_PATTERNS["authorization"]]:
            for pattern in pattern_list:
                if pattern.replace(r"\\", "").replace(r".*", "") in code_snippet.lower():
                    score += 0.2

        return min(score, 1.0)

    @classmethod
    def _check_input_validation_context(cls, code_snippet: str, payload: str) -> float:
        """Check if input validation is present."""
        score = 0.0

        # Check for validation patterns in code
        for pattern in cls.SECURITY_PATTERNS["input_validation"]:
            if pattern.replace(r"\\", "").replace(r".*", "") in code_snippet.lower():
                score += 0.25

        # Check if payload looks like it might be validated (reasonable length, format)
        if len(payload) < 100 and not any(char in payload for char in ["<", ">", "script", "union", "select"]):
            score += 0.2

        return min(score, 1.0)

    @classmethod
    def _check_output_encoding_context(cls, code_snippet: str) -> float:
        """Check if output encoding/sanitization is present for XSS prevention."""
        score = 0.0

        for pattern in cls.SECURITY_PATTERNS["output_encoding"] + cls.SECURITY_PATTERNS["sanitization"]:
            if pattern.replace(r"\\", "").replace(r".*", "") in code_snippet.lower():
                score += 0.3

        return min(score, 1.0)

    @classmethod
    def _check_sql_security_context(cls, code_snippet: str) -> float:
        """Check if SQL security measures are present."""
        score = 0.0

        sql_security_patterns = [
            "prepared.*statement", "parameterized.*query",
            "sqlalchemy", "orm", "execute.*%s", "cursor\.execute",
            "query.*\\?", "bind_param", "prepare.*execute"
        ]

        for pattern in sql_security_patterns:
            if pattern.replace(r".*", "") in code_snippet.lower():
                score += 0.4

        return min(score, 1.0)

    @classmethod
    def _check_business_logic_context(cls, code_snippet: str, payload: str, url: str) -> float:
        """Check if the payload/context suggests legitimate business logic."""
        score = 0.0

        # Check URL for business logic endpoints
        business_urls = ["search", "filter", "sort", "order", "api", "data", "list", "feed"]
        if any(term in url.lower() for term in business_urls):
            score += 0.2

        # Check payload for business logic patterns
        for pattern in cls.BUSINESS_LOGIC_PATTERNS:
            if pattern.replace(r".*", "") in payload.lower():
                score += 0.3

        # Check code for business logic patterns
        for pattern in cls.BUSINESS_LOGIC_PATTERNS:
            if pattern.replace(r".*", "") in code_snippet.lower():
                score += 0.2

        return min(score, 1.0)

    @classmethod
    def _check_command_security_context(cls, code_snippet: str) -> float:
        """Check if command execution security measures are present."""
        score = 0.0

        command_security_patterns = [
            "subprocess", "execfile", "spawn", "popen",
            "escapeshellarg", "escapeshellcmd",
            "shlex", "shell.*false", "array.*args"
        ]

        for pattern in command_security_patterns:
            if pattern.replace(r".*", "") in code_snippet.lower():
                score += 0.4

        return min(score, 1.0)

    @classmethod
    def get_context_explanation(cls, context_factors: Dict[str, float]) -> str:
        """Generate human-readable explanation of context factors."""
        if not context_factors:
            return "No significant context factors detected."

        explanations = []
        for factor, confidence in context_factors.items():
            if confidence > 0.5:
                factor_name = factor.replace("_", " ").title()
                explanations.append(f"Strong evidence of {factor_name} (confidence: {confidence:.1%})")

        if explanations:
            return "Context analysis suggests this may be a false positive due to: " + "; ".join(explanations)
        else:
            return "Limited context factors detected that might reduce false positive risk."