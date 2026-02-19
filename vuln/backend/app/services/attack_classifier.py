"""
Attack type classifier and AI prompts.

Classifies detected attacks and provides chatbot system prompts for developers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..services.remediation import VulnerabilityType


class AttackType(Enum):
    """Supported attack types."""
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    NORMAL = "normal"


@dataclass
class AttackClassification:
    """Result of attack classification."""
    attack_type: AttackType
    confidence: float
    description: str
    risk_indicators: list[str]


class AttackClassifier:
    """Classify attack types from URLs and payloads."""

    # SQL Injection signatures
    SQL_INJECTION_INDICATORS = [
        "union select",
        "union all",
        "drop table",
        "delete from",
        "insert into",
        "update set",
        "exec(",
        "execute(",
        "sleep(",
        "benchmark(",
        "waitfor",
        ";--",
        "' or '",
        '" or "',
        "1=1",
        "or 1=1",
        "and 1=1",
        "comment",
        "/**/",
        "--",
    ]

    # Path Traversal signatures
    PATH_TRAVERSAL_INDICATORS = [
        "../",
        "..\\",
        "....//",
        "....\\\\",
        "..;/",
        "%2e%2e/",
        "%2e%2e\\",
        "..%2f",
        "..%5c",
        "/etc/passwd",
        "/etc/shadow",
        "c:\\windows",
        "c:\\winnt",
        "windows\\system32",
        ".env",
        ".htaccess",
        "web.config",
        "config.php",
    ]

    # XSS signatures
    XSS_INDICATORS = [
        "<script",
        "</script>",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "onmouseenter=",
        "javascript:",
        "data:text/html",
        "<iframe",
        "<img",
        "<svg",
        "<embed",
        "<object",
        "eval(",
        "innerHTML",
        "dangerouslySetInnerHTML",
        "<body",
        "alert(",
        "confirm(",
        "prompt(",
    ]

    # Command Injection signatures
    COMMAND_INJECTION_INDICATORS = [
        ";ls",
        ";cat",
        ";whoami",
        ";id",
        ";pwd",
        "&ls",
        "&cat",
        "|ls",
        "|cat",
        "||",
        "&&",
        "\n",
        "`",
        "$()",
        "$(cat",
        "backtick",
        "nc -l",
        "ncat",
        "bash",
        "/bin/sh",
        "cmd.exe",
        "powershell",
    ]

    @classmethod
    def classify(
        cls,
        url: str,
        payload: str,
        context: Optional[str] = None,
    ) -> AttackClassification:
        """
        Classify attack type from URL and payload.

        Args:
            url: URL being attacked
            payload: Payload or parameters
            context: Optional additional context

        Returns:
            AttackClassification with type and confidence
        """
        combined = f"{url} {payload} {context or ''}".lower()

        # Score each attack type
        sql_score = cls._count_indicators(combined, cls.SQL_INJECTION_INDICATORS)
        path_score = cls._count_indicators(combined, cls.PATH_TRAVERSAL_INDICATORS)
        xss_score = cls._count_indicators(combined, cls.XSS_INDICATORS)
        cmd_score = cls._count_indicators(combined, cls.COMMAND_INJECTION_INDICATORS)

        # Boost command injection if shell operators are present
        if ";" in combined or "|" in combined or "`" in combined or "$(" in combined:
            cmd_score += 2

        # Boost SQL injection for common patterns
        if "union select" in combined or "drop table" in combined:
            sql_score += 2

        # Determine the attack type
        scores = {
            AttackType.SQL_INJECTION: sql_score,
            AttackType.PATH_TRAVERSAL: path_score,
            AttackType.XSS: xss_score,
            AttackType.COMMAND_INJECTION: cmd_score,
        }

        max_score = max(scores.values())
        if max_score == 0:
            return AttackClassification(
                attack_type=AttackType.NORMAL,
                confidence=1.0,
                description="No attack patterns detected",
                risk_indicators=[],
            )

        # Determine which attack type has the highest score
        attack_type = max(scores, key=scores.get)
        # Adjust confidence calculation - higher base confidence for matches
        confidence = min(0.5 + (max_score / 5.0), 1.0)  # Start at 0.5, add up to 0.5 more

        # Get indicators for this attack type
        indicators = cls._get_detected_indicators(combined, attack_type)

        attack_descriptions = {
            AttackType.SQL_INJECTION: "SQL Injection attempt detected. User input may be interpreted as SQL code.",
            AttackType.PATH_TRAVERSAL: "Path Traversal (Directory Traversal) attempt detected. User input may access unauthorized files.",
            AttackType.XSS: "Cross-Site Scripting (XSS) attempt detected. User input may execute malicious JavaScript.",
            AttackType.COMMAND_INJECTION: "Command Injection attempt detected. User input may execute arbitrary system commands.",
            AttackType.NORMAL: "No attack patterns detected.",
        }

        return AttackClassification(
            attack_type=attack_type,
            confidence=confidence,
            description=attack_descriptions[attack_type],
            risk_indicators=indicators,
        )

    @staticmethod
    def _count_indicators(text: str, indicators: list[str]) -> int:
        """Count how many indicators are present in text."""
        return sum(1 for indicator in indicators if indicator in text)

    @classmethod
    def _get_detected_indicators(cls, text: str, attack_type: AttackType) -> list[str]:
        """Get which specific indicators were detected."""
        indicators_map = {
            AttackType.SQL_INJECTION: cls.SQL_INJECTION_INDICATORS,
            AttackType.PATH_TRAVERSAL: cls.PATH_TRAVERSAL_INDICATORS,
            AttackType.XSS: cls.XSS_INDICATORS,
            AttackType.COMMAND_INJECTION: cls.COMMAND_INJECTION_INDICATORS,
        }

        indicators = indicators_map.get(attack_type, [])
        return [ind for ind in indicators if ind in text][:5]  # Return top 5


class SecurityChatbotPrompts:
    """System prompts for developer-focused security chatbot."""

    CHATBOT_SYSTEM_PROMPT = """You are a developer-focused application security assistant.

Context you receive:
- Detected vulnerability type
- Risk level
- Code snippet
- Programming language
- Attack pattern observed in URL

Rules:
- Answer only security-related questions.
- Explain vulnerabilities clearly, without jargon.
- Suggest secure coding practices.
- Do not encourage exploitation.
- Always focus on fixing and prevention.

You should help developers:
- Understand why their code is vulnerable.
- Learn how to fix it correctly.
- Avoid the same issue in future.

Supported vulnerabilities:
- SQL Injection: Unauthorized database access via query manipulation
- Path Traversal: Unauthorized file system access via directory escape
- XSS (Cross-Site Scripting): Malicious script injection into web pages
- Command Injection: Unauthorized system command execution

When discussing any vulnerability:
1. Explain the root cause in simple terms
2. Show the vulnerable pattern
3. Provide a secure fix with explanation
4. Link to prevention best practices"""

    REMEDIATION_SYSTEM_PROMPT = """You are a secure code remediation engine.

Input:
1. URL used in request
2. Backend code snippet
3. Detected vulnerability type
4. Programming language

Tasks:
- Identify the exact vulnerable line(s) in the code.
- Explain why the code is vulnerable in simple terms.
- Highlight the unsafe part.
- Generate a secure, production-ready fixed version of the same code.
- Follow industry best practices.
- Do not change application logic.
- Add brief comments explaining the fix.

Output format:
1. Vulnerable Code (highlighted)
2. Vulnerability Explanation
3. Secure Fixed Code
4. Why this fix works

Additional Guidelines:
- Use language-specific best practices (parameterized queries for SQL, path validation for file access, etc.)
- Include comments explaining WHY each change makes the code secure
- Maintain the original business logic
- Provide multiple fix options when applicable (ORM, prepared statements, sanitization libraries, etc.)"""

    ATTACK_CLASSIFICATION_PROMPT = """Classify the following input as one of:
- SQL Injection
- Path Traversal
- XSS
- Command Injection
- Normal

Return only the attack type and confidence score (0.0-1.0).

Format: TYPE | CONFIDENCE

Example outputs:
- SQL Injection | 0.95
- XSS | 0.87
- Path Traversal | 0.42
- Normal | 0.99"""

    @staticmethod
    def get_chatbot_prompt() -> str:
        """Get the chatbot system prompt."""
        return SecurityChatbotPrompts.CHATBOT_SYSTEM_PROMPT

    @staticmethod
    def get_remediation_prompt() -> str:
        """Get the code remediation prompt."""
        return SecurityChatbotPrompts.REMEDIATION_SYSTEM_PROMPT

    @staticmethod
    def get_classification_prompt() -> str:
        """Get the attack classification prompt."""
        return SecurityChatbotPrompts.ATTACK_CLASSIFICATION_PROMPT

    @staticmethod
    def get_all_prompts() -> dict[str, str]:
        """Get all system prompts."""
        return {
            "chatbot": SecurityChatbotPrompts.get_chatbot_prompt(),
            "remediation": SecurityChatbotPrompts.get_remediation_prompt(),
            "classification": SecurityChatbotPrompts.get_classification_prompt(),
        }
