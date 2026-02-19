"""
Test suite for attack classification and remediation.

Tests for XSS, Command Injection, SQL Injection, and Path Traversal attacks.
"""

import pytest
from app.services.attack_classifier import AttackClassifier, AttackType
from app.services.remediation import RemediationEngine, VulnerabilityType


class TestAttackClassification:
    """Test attack type classification."""

    def test_classify_sql_injection_union_select(self) -> None:
        """Test SQL Injection classification with UNION SELECT."""
        result = AttackClassifier.classify(
            "https://example.com/search?q=test",
            "q=1' UNION SELECT username, password FROM users--",
        )
        assert result.attack_type == AttackType.SQL_INJECTION
        assert result.confidence > 0.7

    def test_classify_sql_injection_drop_table(self) -> None:
        """Test SQL Injection classification with DROP TABLE."""
        result = AttackClassifier.classify(
            "https://example.com/users",
            "id=1; DROP TABLE users;--",
        )
        assert result.attack_type == AttackType.SQL_INJECTION
        assert result.confidence > 0.6

    def test_classify_path_traversal_etc_passwd(self) -> None:
        """Test Path Traversal classification accessing /etc/passwd."""
        result = AttackClassifier.classify(
            "https://example.com/files/download",
            "file=../../../../etc/passwd",
        )
        assert result.attack_type == AttackType.PATH_TRAVERSAL
        assert result.confidence > 0.7

    def test_classify_path_traversal_windows(self) -> None:
        """Test Path Traversal classification for Windows paths."""
        result = AttackClassifier.classify(
            "https://example.com/download",
            "file=..\\..\\..\\windows\\system32\\config\\sam",
        )
        assert result.attack_type == AttackType.PATH_TRAVERSAL
        assert result.confidence > 0.6

    def test_classify_xss_script_tag(self) -> None:
        """Test XSS classification with script tag."""
        result = AttackClassifier.classify(
            "https://example.com/comment",
            "comment=<script>alert('XSS')</script>",
        )
        assert result.attack_type == AttackType.XSS
        assert result.confidence > 0.8

    def test_classify_xss_event_handler(self) -> None:
        """Test XSS classification with event handler."""
        result = AttackClassifier.classify(
            "https://example.com/profile",
            "bio=<img src=x onerror=alert('XSS')>",
        )
        assert result.attack_type == AttackType.XSS
        assert result.confidence > 0.8

    def test_classify_xss_svg_injection(self) -> None:
        """Test XSS classification with SVG injection."""
        result = AttackClassifier.classify(
            "https://example.com/upload",
            "content=<svg onload=alert('XSS')>",
        )
        assert result.attack_type == AttackType.XSS
        assert result.confidence > 0.7

    def test_classify_command_injection_unix(self) -> None:
        """Test Command Injection classification with Unix commands."""
        result = AttackClassifier.classify(
            "https://example.com/ping",
            "host=8.8.8.8; cat /etc/passwd",
        )
        assert result.attack_type == AttackType.COMMAND_INJECTION
        assert result.confidence > 0.7

    def test_classify_command_injection_pipe(self) -> None:
        """Test Command Injection classification with pipe operator."""
        result = AttackClassifier.classify(
            "https://example.com/lookup",
            "domain=example.com | nc -l -p 1234",
        )
        assert result.attack_type == AttackType.COMMAND_INJECTION
        assert result.confidence > 0.6

    def test_classify_command_injection_backtick(self) -> None:
        """Test Command Injection classification with backticks."""
        result = AttackClassifier.classify(
            "https://example.com/search",
            "query=`whoami`",
        )
        assert result.attack_type == AttackType.COMMAND_INJECTION
        assert result.confidence > 0.6

    def test_classify_command_injection_command_substitution(self) -> None:
        """Test Command Injection classification with command substitution."""
        result = AttackClassifier.classify(
            "https://example.com/test",
            "input=$(cat /etc/passwd)",
        )
        assert result.attack_type == AttackType.COMMAND_INJECTION
        assert result.confidence > 0.6

    def test_classify_normal_input(self) -> None:
        """Test that normal input is classified correctly."""
        result = AttackClassifier.classify(
            "https://example.com/search?q=test",
            "q=hello+world&sort=date",
        )
        assert result.attack_type == AttackType.NORMAL
        assert result.confidence > 0.9

    def test_classify_with_context(self) -> None:
        """Test classification with additional context."""
        result = AttackClassifier.classify(
            "https://example.com/api/user",
            "name=John",
            context="suspicious_user_agent=bad_bot",
        )
        assert result.attack_type in [
            AttackType.NORMAL,
            AttackType.SQL_INJECTION,
            AttackType.XSS,
            AttackType.COMMAND_INJECTION,
            AttackType.PATH_TRAVERSAL,
        ]


class TestRemediationEngine:
    """Test code remediation engine."""

    def test_remediate_sql_injection_python(self) -> None:
        """Test SQL Injection remediation for Python."""
        code = "user_id = request.args.get('id')\nquery = f\"SELECT * FROM users WHERE id = {user_id}\""
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.SQL_INJECTION,
            "python",
        )
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert len(result.vulnerable_lines) > 0
        assert "parameterized" in result.explanation.lower() or "prepared" in result.explanation.lower()
        assert len(result.secure_code) > 0
        assert "?" in result.secure_code or "%s" in result.secure_code

    def test_remediate_sql_injection_javascript(self) -> None:
        """Test SQL Injection remediation for JavaScript."""
        code = "const query = `SELECT * FROM users WHERE email = '${email}'`;"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.SQL_INJECTION,
            "javascript",
        )
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert "parameterized" in result.explanation.lower() or "prepared" in result.explanation.lower()
        assert len(result.secure_code) > 0

    def test_remediate_path_traversal_python(self) -> None:
        """Test Path Traversal remediation for Python."""
        code = "filename = request.args.get('file')\nwith open(f'uploads/{filename}') as f:"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.PATH_TRAVERSAL,
            "python",
        )
        assert result.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
        assert "path" in result.explanation.lower() or "traversal" in result.explanation.lower()
        assert len(result.secure_code) > 0
        assert "resolve" in result.secure_code or "realpath" in result.secure_code

    def test_remediate_path_traversal_javascript(self) -> None:
        """Test Path Traversal remediation for JavaScript."""
        code = "const filepath = `uploads/${userInput}`;\nfs.readFileSync(filepath);"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.PATH_TRAVERSAL,
            "javascript",
        )
        assert result.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
        assert len(result.secure_code) > 0
        assert "resolve" in result.secure_code.lower()

    def test_remediate_xss_python(self) -> None:
        """Test XSS remediation for Python."""
        code = "username = request.args.get('name')\nreturn f'<h1>Welcome {username}</h1>'"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.XSS,
            "python",
        )
        assert result.vulnerability_type == VulnerabilityType.XSS
        assert "escape" in result.explanation.lower() or "xss" in result.explanation.lower()
        assert len(result.secure_code) > 0
        assert "escape" in result.secure_code.lower() or "autoescape" in result.secure_code.lower()

    def test_remediate_xss_javascript(self) -> None:
        """Test XSS remediation for JavaScript."""
        code = "document.getElementById('name').innerHTML = userInput;"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.XSS,
            "javascript",
        )
        assert result.vulnerability_type == VulnerabilityType.XSS
        assert len(result.secure_code) > 0
        assert "textContent" in result.secure_code or "sanitize" in result.secure_code.lower()

    def test_remediate_command_injection_python(self) -> None:
        """Test Command Injection remediation for Python."""
        code = "hostname = request.args.get('host')\nos.system(f'ping {hostname}')"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.COMMAND_INJECTION,
            "python",
        )
        assert result.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
        assert "command" in result.explanation.lower() or "shell" in result.explanation.lower()
        assert len(result.secure_code) > 0
        assert "subprocess" in result.secure_code

    def test_remediate_command_injection_javascript(self) -> None:
        """Test Command Injection remediation for JavaScript."""
        code = "child_process.exec(`ping ${hostname}`)"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.COMMAND_INJECTION,
            "javascript",
        )
        assert result.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
        assert len(result.secure_code) > 0
        assert "execFile" in result.secure_code or "spawn" in result.secure_code

    def test_vulnerable_lines_detection(self) -> None:
        """Test that vulnerable lines are correctly detected."""
        code = """
def unsafe_query(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    execute(query)
"""
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.SQL_INJECTION,
            "python",
        )
        assert len(result.vulnerable_lines) > 0
        assert 2 in result.vulnerable_lines or 3 in result.vulnerable_lines  # Line with f-string or execute

    def test_unknown_vulnerability_type(self) -> None:
        """Test handling of unknown vulnerability type."""
        code = "x = 1"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.UNKNOWN,
            "python",
        )
        assert result.vulnerability_type == VulnerabilityType.UNKNOWN
        assert "not yet available" in result.explanation.lower()

    def test_unsupported_language(self) -> None:
        """Test handling of unsupported language."""
        code = "print('hello')"
        result = RemediationEngine.analyze_code(
            code,
            VulnerabilityType.SQL_INJECTION,
            "ruby",  # Not yet supported
        )
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert "not yet available" in result.explanation.lower()


class TestSecurityPrompts:
    """Test security chatbot prompts."""

    def test_chatbot_prompt_contains_guidelines(self) -> None:
        """Test that chatbot prompt contains security guidelines."""
        from app.services.attack_classifier import SecurityChatbotPrompts

        prompt = SecurityChatbotPrompts.get_chatbot_prompt()
        assert len(prompt) > 0
        assert "developer" in prompt.lower() or "security" in prompt.lower()
        assert "SQL Injection" in prompt or "vulnerability" in prompt.lower()

    def test_remediation_prompt_format(self) -> None:
        """Test that remediation prompt has correct structure."""
        from app.services.attack_classifier import SecurityChatbotPrompts

        prompt = SecurityChatbotPrompts.get_remediation_prompt()
        assert len(prompt) > 0
        assert "vulnerable" in prompt.lower()
        assert "code" in prompt.lower()
        assert "fix" in prompt.lower()

    def test_classification_prompt_format(self) -> None:
        """Test that classification prompt has correct format."""
        from app.services.attack_classifier import SecurityChatbotPrompts

        prompt = SecurityChatbotPrompts.get_classification_prompt()
        assert len(prompt) > 0
        assert "SQL Injection" in prompt or "XSS" in prompt
        assert "confidence" in prompt.lower()

    def test_get_all_prompts(self) -> None:
        """Test that all prompts can be retrieved."""
        from app.services.attack_classifier import SecurityChatbotPrompts

        prompts = SecurityChatbotPrompts.get_all_prompts()
        assert "chatbot" in prompts
        assert "remediation" in prompts
        assert "classification" in prompts
        assert all(len(v) > 0 for v in prompts.values())
