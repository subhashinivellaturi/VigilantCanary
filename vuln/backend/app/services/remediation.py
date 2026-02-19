"""
Secure code remediation engine.

Provides automated detection and remediation of vulnerabilities in code snippets.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VulnerabilityType(Enum):
    """Supported vulnerability types."""
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    UNKNOWN = "unknown"


@dataclass
class RemediationResult:
    """Result of code remediation analysis."""
    vulnerability_type: VulnerabilityType
    vulnerable_lines: list[int]
    explanation: str
    secure_code: str
    why_it_works: str
    cwe_id: Optional[str] = None
    cve_references: Optional[list[str]] = None
    owasp_category: Optional[str] = None


class RemediationEngine:
    """Secure code remediation engine."""

    # CWE mappings for vulnerabilities
    CWE_MAPPINGS = {
        VulnerabilityType.SQL_INJECTION: "CWE-89",
        VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
        VulnerabilityType.XSS: "CWE-79",
        VulnerabilityType.COMMAND_INJECTION: "CWE-78",
    }

    # OWASP Top 10 mappings
    OWASP_MAPPINGS = {
        VulnerabilityType.SQL_INJECTION: "A03:2021-Injection",
        VulnerabilityType.PATH_TRAVERSAL: "A01:2021-Broken Access Control",
        VulnerabilityType.XSS: "A03:2021-Injection",
        VulnerabilityType.COMMAND_INJECTION: "A03:2021-Injection",
    }

    # CVE references (examples - in production, this would be a database)
    CVE_REFERENCES = {
        VulnerabilityType.SQL_INJECTION: ["CVE-2023-1234", "CVE-2022-5678"],
        VulnerabilityType.PATH_TRAVERSAL: ["CVE-2023-2345", "CVE-2021-3456"],
        VulnerabilityType.XSS: ["CVE-2023-3456", "CVE-2022-6789"],
        VulnerabilityType.COMMAND_INJECTION: ["CVE-2023-4567", "CVE-2021-7890"],
    }

    # SQL Injection fixes
    SQL_INJECTION_REMEDIATIONS = {
        "python": {
            "explanation": "SQL Injection occurs when user input is directly concatenated into SQL queries without using parameterized queries. An attacker can break out of the query string and execute arbitrary SQL commands.",
            "vulnerable_pattern": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
            "secure_code": """# SECURE: Use parameterized queries (prepared statements)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# Alternative with SQLAlchemy ORM:
user = db.session.query(User).filter(User.id == user_id).first()""",
            "why_it_works": "Parameterized queries treat user input as data, not code. The database driver handles escaping automatically, preventing injection attacks.",
        },
        "javascript": {
            "explanation": "SQL Injection in JavaScript/Node.js occurs when user input is directly inserted into SQL queries without using parameterized queries or prepared statements.",
            "vulnerable_pattern": "const query = `SELECT * FROM users WHERE email = '${email}'`;",
            "secure_code": "// SECURE: Use parameterized queries with prepared statements\nconst query = 'SELECT * FROM users WHERE email = ?';\ndb.query(query, [email], (err, results) => {\n  // Handle results\n});\n\n// Or with Sequelize ORM:\nconst user = await User.findOne({ where: { email } });",
            "why_it_works": "Parameterized queries separate SQL structure from user input. The database driver escapes special characters, neutralizing injection attacks.",
        },
        "php": {
            "explanation": "SQL Injection in PHP occurs when user input is directly concatenated into SQL queries without using prepared statements or parameterized queries.",
            "vulnerable_pattern": "$query = \"SELECT * FROM users WHERE email = '$email'\";",
            "secure_code": "// SECURE: Use PDO prepared statements\n$stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = ?\");\n$stmt->execute([$email]);\n$user = $stmt->fetch();\n\n// Alternative with mysqli:\n$stmt = $mysqli->prepare(\"SELECT * FROM users WHERE email = ?\");\n$stmt->bind_param(\"s\", $email);\n$stmt->execute();",
            "why_it_works": "Prepared statements separate SQL structure from user input. The database driver properly escapes special characters, preventing injection attacks.",
        },
        "java": {
            "explanation": "SQL Injection in Java occurs when user input is directly concatenated into SQL queries without using prepared statements or parameterized queries.",
            "vulnerable_pattern": "String query = \"SELECT * FROM users WHERE email = '\" + email + \"'\";",
            "secure_code": "// SECURE: Use PreparedStatement\nString query = \"SELECT * FROM users WHERE email = ?\";\nPreparedStatement stmt = connection.prepareStatement(query);\nstmt.setString(1, email);\nResultSet rs = stmt.executeQuery();\n\n// Or with JPA/Hibernate:\n@Repository\npublic interface UserRepository extends JpaRepository<User, Long> {\n    User findByEmail(String email);\n}\n\n// Usage:\nUser user = userRepository.findByEmail(email);",
            "why_it_works": "PreparedStatement automatically escapes special characters. JPA/Hibernate uses parameterized queries internally, preventing injection attacks.",
        },
        "go": {
            "explanation": "SQL Injection in Go occurs when user input is directly concatenated into SQL queries without using prepared statements or parameterized queries.",
            "vulnerable_pattern": "query := fmt.Sprintf(\"SELECT * FROM users WHERE email = '%s'\", email)",
            "secure_code": """// SECURE: Use prepared statements
query := "SELECT * FROM users WHERE email = $1"
row := db.QueryRow(query, email)
var user User
err := row.Scan(&user.ID, &user.Email, &user.Name)

// Or with sqlx:
query := "SELECT * FROM users WHERE email = ?"
var user User
err := db.Get(&user, query, email)

// Or with GORM:
var user User
result := db.Where("email = ?", email).First(&user)""",
            "why_it_works": "Prepared statements ($1, ?) separate SQL structure from user input. The database driver handles escaping, preventing injection attacks.",
        },
    }

    # Path Traversal fixes
    PATH_TRAVERSAL_REMEDIATIONS = {
        "python": {
            "explanation": "Path Traversal (Directory Traversal) occurs when user input is used to construct file paths without validation. Attackers can use '../' to access files outside the intended directory.",
            "vulnerable_pattern": "file_path = f'uploads/{user_input}'",
            "secure_code": """# SECURE: Use path normalization and validation
import os
from pathlib import Path

base_dir = Path('uploads').resolve()
requested_path = Path(user_input).resolve()

# Ensure the resolved path is within base_dir
if not str(requested_path).startswith(str(base_dir)):
    raise ValueError("Path traversal attempt detected")

file_path = requested_path""",
            "why_it_works": "Path.resolve() converts relative paths to absolute paths. Checking if the resolved path starts with the base directory ensures containment.",
        },
        "javascript": {
            "explanation": "Path Traversal in Node.js occurs when user input controls file paths without validation.",
            "vulnerable_pattern": "fs.readFileSync(`uploads/${userInput}`)",
            "secure_code": """// SECURE: Normalize and validate file paths
const path = require('path');
const fs = require('fs');

const baseDir = path.resolve('uploads');
const requestedPath = path.resolve(path.join('uploads', userInput));

// Ensure the path is within baseDir
if (!requestedPath.startsWith(baseDir)) {
  throw new Error('Path traversal attempt detected');
}

fs.readFileSync(requestedPath);""",
            "why_it_works": "path.resolve() converts relative paths to absolute. Checking containment within baseDir prevents directory escape.",
        },
        "php": {
            "explanation": "Path Traversal in PHP occurs when user input is used to construct file paths without validation.",
            "vulnerable_pattern": "$file = 'uploads/' . $_GET['file'];",
            "secure_code": """// SECURE: Use realpath() and validate paths
$baseDir = realpath('uploads/');
$requestedPath = realpath('uploads/' . $_GET['file']);

// Ensure the path is within baseDir
if ($requestedPath === false || strpos($requestedPath, $baseDir) !== 0) {
    die('Path traversal attempt detected');
}

$file = $requestedPath;""",
            "why_it_works": "realpath() resolves symbolic links and relative paths. Checking if the resolved path starts with baseDir ensures containment.",
        },
        "java": {
            "explanation": "Path Traversal in Java occurs when user input is used to construct file paths without validation.",
            "vulnerable_pattern": "File file = new File(\"uploads/\" + userInput);",
            "secure_code": """// SECURE: Use Path normalization and validation
import java.nio.file.*;
import java.io.IOException;

Path baseDir = Paths.get("uploads").toAbsolutePath().normalize();
Path requestedPath = Paths.get("uploads", userInput).toAbsolutePath().normalize();

// Ensure the path is within baseDir
if (!requestedPath.startsWith(baseDir)) {
    throw new SecurityException("Path traversal attempt detected");
}

File file = requestedPath.toFile();""",
            "why_it_works": "Paths.get().toAbsolutePath().normalize() resolves relative paths. Checking startsWith() ensures the path stays within the base directory.",
        },
        "go": {
            "explanation": "Path Traversal in Go occurs when user input is used to construct file paths without validation.",
            "vulnerable_pattern": "filePath := filepath.Join(\"uploads\", userInput)",
            "secure_code": """// SECURE: Use filepath.Clean and validation
import (
    "path/filepath"
    "strings"
    "errors"
)

baseDir, _ := filepath.Abs("uploads")
requestedPath, _ := filepath.Abs(filepath.Join("uploads", userInput))
cleanPath := filepath.Clean(requestedPath)

// Ensure the path is within baseDir
if !strings.HasPrefix(cleanPath, baseDir) {
    return errors.New("path traversal attempt detected")
}

filePath := cleanPath""",
            "why_it_works": "filepath.Clean() resolves relative paths and removes redundant elements. Checking HasPrefix() ensures the path stays within the base directory.",
        },
    }

    # XSS fixes
    XSS_REMEDIATIONS = {
        "python": {
            "explanation": "XSS (Cross-Site Scripting) occurs when user input is rendered in HTML/JavaScript without proper escaping. Attackers inject malicious scripts that execute in users' browsers.",
            "vulnerable_pattern": "return f'<h1>Welcome {user_name}</h1>'",
            "secure_code": """# SECURE: Escape HTML special characters
from html import escape

escaped_name = escape(user_name)
return f'<h1>Welcome {escaped_name}</h1>'

# Or with templating engines (recommended):
from jinja2 import Environment

env = Environment(autoescape=True)
template = env.from_string('<h1>Welcome {{ name }}</h1>')
return template.render(name=user_name)""",
            "why_it_works": "HTML escaping converts special characters (<, >, &, etc.) to entities (&lt;, &gt;, &amp;). Templating engines with autoescape=True escape by default.",
        },
        "javascript": {
            "explanation": "XSS in JavaScript occurs when user input is directly inserted into the DOM without escaping.",
            "vulnerable_pattern": "document.getElementById('name').innerHTML = userInput;",
            "secure_code": """// SECURE: Use textContent for text, or sanitized innerHTML
// For text content:
document.getElementById('name').textContent = userInput;

// For HTML (with sanitization):
import DOMPurify from 'dompurify';

const cleanInput = DOMPurify.sanitize(userInput);
document.getElementById('name').innerHTML = cleanInput;

// Or use DOM methods:
const para = document.createElement('p');
para.textContent = userInput;
document.body.appendChild(para);""",
            "why_it_works": "textContent treats input as plain text. DOMPurify removes dangerous HTML/JS. DOM methods prevent direct HTML injection.",
        },
        "php": {
            "explanation": "XSS in PHP occurs when user input is output to HTML without proper escaping.",
            "vulnerable_pattern": "echo '<h1>Welcome ' . $_GET['name'] . '</h1>';",
            "secure_code": """// SECURE: Use htmlspecialchars() for HTML output
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo '<h1>Welcome ' . $name . '</h1>';

// Or with templating engines (recommended):
// Twig template: <h1>Welcome {{ name }}</h1>
// PHP code: $twig->render('template.twig', ['name' => $_GET['name']]);""",
            "why_it_works": "htmlspecialchars() converts special HTML characters to entities. ENT_QUOTES ensures both single and double quotes are escaped. Templating engines escape by default.",
        },
        "java": {
            "explanation": "XSS in Java occurs when user input is output to HTML without proper escaping.",
            "vulnerable_pattern": "out.println(\"<h1>Welcome \" + userName + \"</h1>\");",
            "secure_code": "// SECURE: Use StringEscapeUtils or OWASP Java Encoder\nimport org.apache.commons.text.StringEscapeUtils;\n\n// For HTML output:\nString safeName = StringEscapeUtils.escapeHtml4(userName);\nout.println(\"<h1>Welcome \" + safeName + \"</h1>\");\n\n// Or with OWASP Java Encoder:\nimport org.owasp.encoder.Encode;\nString safeName = Encode.forHtml(userName);\nout.println(\"<h1>Welcome \" + safeName + \"</h1>\");\n\n// For templating engines (recommended):\n// Thymeleaf: <h1>Welcome <span th:text=\"${name}\"></span></h1>\n// Automatically escapes by default",
            "why_it_works": "StringEscapeUtils.escapeHtml4() converts HTML special characters to entities. OWASP Java Encoder provides comprehensive encoding. Templating engines escape by default.",
        },
        "go": {
            "explanation": "XSS in Go occurs when user input is output to HTML without proper escaping.",
            "vulnerable_pattern": "fmt.Fprintf(w, \"<h1>Welcome %s</h1>\", userName)",
            "secure_code": "// SECURE: Use html.EscapeString for HTML output\nimport (\n    \"html\"\n    \"fmt\"\n)\n\nsafeName := html.EscapeString(userName)\nfmt.Fprintf(w, \"<h1>Welcome %s</h1>\", safeName)\n\n// Or with templating engines (recommended):\nimport \"html/template\"\n\ntmpl := template.Must(template.New(\"example\").Parse(\"<h1>Welcome {{.Name}}</h1>\"))\ndata := struct{ Name string }{userName}\ntmpl.Execute(w, data)",
            "why_it_works": "html.EscapeString() converts HTML special characters to entities. Go's html/template package automatically escapes content to prevent XSS.",
        },
    }

    # Command Injection fixes
    COMMAND_INJECTION_REMEDIATIONS = {
        "python": {
            "explanation": "Command Injection occurs when user input is passed to shell commands without proper escaping. Attackers can chain commands using operators like ;, |, &&, etc.",
            "vulnerable_pattern": "os.system(f'ping {hostname}')",
            "secure_code": "# SECURE: Use subprocess with list of arguments (no shell parsing)\nimport subprocess\n\n# Recommended: Use list form without shell=True\nresult = subprocess.run(['ping', '-c', '1', hostname], \n                       capture_output=True, \n                       text=True,\n                       timeout=5)\n\n# For complex commands, validate input strictly\nimport shlex\nif not re.match(r'^[a-zA-Z0-9.-]+$', hostname):\n    raise ValueError('Invalid hostname')\nresult = subprocess.run(f'ping -c 1 {hostname}', \n                       shell=True,\n                       capture_output=True)",
            "why_it_works": "Passing arguments as a list prevents shell interpretation. shell=False (default) doesn't invoke the shell. Input validation adds defense-in-depth.",
        },
        "javascript": {
            "explanation": "Command Injection in Node.js occurs when user input is passed to shell execution functions without proper handling.",
            "vulnerable_pattern": "child_process.exec(`ping ${hostname}`)",
            "secure_code": "// SECURE: Use execFile or spawn instead of exec\nconst { execFile, spawn } = require('child_process');\nconst { promisify } = require('util');\n\n// Recommended: execFile (no shell interpretation)\nconst execFileAsync = promisify(execFile);\nconst { stdout } = await execFileAsync('ping', ['-c', '1', hostname]);\n\n// Or use spawn for streaming:\nconst ping = spawn('ping', ['-c', '1', hostname]);\nping.stdout.on('data', (data) => console.log(data));\n\n// Never use exec() with user input",
            "why_it_works": "execFile/spawn pass arguments as array, preventing shell injection. No shell spawning means no command chaining possible.",
        },
        "php": {
            "explanation": "Command Injection in PHP occurs when user input is passed to system functions without proper escaping.",
            "vulnerable_pattern": "system('ping ' . $_GET['host']);",
            "secure_code": "// SECURE: Use escapeshellarg() and escapeshellcmd()\n$host = escapeshellarg($_GET['host']);\nsystem('ping -c 1 ' . $host);\n\n// Or better: Avoid shell execution entirely\n// Use PHP functions or libraries instead\n$ping = new Ping($host);\n$ping->setCount(1);\n$result = $ping->ping();\n\n// For allowed commands only:\n$allowed_hosts = ['127.0.0.1', 'localhost', '8.8.8.8'];\nif (in_array($_GET['host'], $allowed_hosts)) {\n    system('ping -c 1 ' . escapeshellarg($_GET['host']));\n}",
            "why_it_works": "escapeshellarg() escapes shell metacharacters in arguments. Whitelisting allowed values prevents injection. Using PHP libraries avoids shell entirely.",
        },
        "java": {
            "explanation": "Command Injection in Java occurs when user input is passed to ProcessBuilder or Runtime.exec() without proper validation.",
            "vulnerable_pattern": "Runtime.getRuntime().exec(\"ping \" + hostname);",
            "secure_code": "// SECURE: Use ProcessBuilder with argument array\nProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", hostname);\nProcess process = pb.start();\nint exitCode = process.waitFor();\n\n// Or with input validation:\nimport java.util.regex.Pattern;\nPattern pattern = Pattern.compile(\"^[a-zA-Z0-9.-]+$\");\nif (!pattern.matcher(hostname).matches()) {\n    throw new IllegalArgumentException(\"Invalid hostname\");\n}\nProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", hostname);\nProcess process = pb.start();\n\n// Never use string concatenation with exec()",
            "why_it_works": "ProcessBuilder with array arguments prevents shell interpretation. Input validation using regex ensures only safe characters are accepted.",
        },
        "go": {
            "explanation": "Command Injection in Go occurs when user input is passed to exec.Command without proper validation.",
            "vulnerable_pattern": "cmd := exec.Command(\"ping\", \"-c\", \"1\", hostname)",
            "secure_code": "// SECURE: Use exec.Command with argument validation\nimport (\n    \"os/exec\"\n    \"regexp\"\n    \"errors\"\n)\n\n// Validate input\nvalidHostname := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)\nif !validHostname.MatchString(hostname) {\n    return errors.New(\"invalid hostname\")\n}\n\n// Use exec.Command safely\ncmd := exec.Command(\"ping\", \"-c\", \"1\", hostname)\noutput, err := cmd.Output()\n\n// Or use a whitelist approach:\nallowedHosts := []string{\"127.0.0.1\", \"localhost\", \"8.8.8.8\"}\nisAllowed := false\nfor _, allowed := range allowedHosts {\n    if hostname == allowed {\n        isAllowed = true\n        break\n    }\n}\nif !isAllowed {\n    return errors.New(\"hostname not allowed\")\n}\ncmd := exec.Command(\"ping\", \"-c\", \"1\", hostname)\noutput, err := cmd.Output()",
            "why_it_works": "exec.Command with array arguments prevents shell injection. Input validation ensures only safe hostnames are accepted. Whitelisting provides additional security.",
        },
    }

    @classmethod
    def analyze_code(
        cls,
        code_snippet: str,
        vulnerability_type: VulnerabilityType,
        language: str,
        url: Optional[str] = None,
    ) -> RemediationResult:
        """
        Analyze code and generate remediation.

        Args:
            code_snippet: The code to analyze
            vulnerability_type: Type of vulnerability detected
            language: Programming language (python, javascript, etc.)
            url: URL used in request (optional context)

        Returns:
            RemediationResult with analysis and fixes
        """
        # Determine which remediation to use
        remediations = None
        vulnerable_lines = cls._find_vulnerable_lines(code_snippet, vulnerability_type)

        if vulnerability_type == VulnerabilityType.SQL_INJECTION:
            remediations = cls.SQL_INJECTION_REMEDIATIONS.get(language.lower())
        elif vulnerability_type == VulnerabilityType.PATH_TRAVERSAL:
            remediations = cls.PATH_TRAVERSAL_REMEDIATIONS.get(language.lower())
        elif vulnerability_type == VulnerabilityType.XSS:
            remediations = cls.XSS_REMEDIATIONS.get(language.lower())
        elif vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
            remediations = cls.COMMAND_INJECTION_REMEDIATIONS.get(language.lower())

        if not remediations:
            return RemediationResult(
                vulnerability_type=vulnerability_type,
                vulnerable_lines=vulnerable_lines,
                explanation=f"Remediation for {vulnerability_type.value} in {language} not yet available.",
                secure_code="",
                why_it_works="",
                cwe_id=cls.CWE_MAPPINGS.get(vulnerability_type),
                cve_references=cls.CVE_REFERENCES.get(vulnerability_type),
                owasp_category=cls.OWASP_MAPPINGS.get(vulnerability_type),
            )

        return RemediationResult(
            vulnerability_type=vulnerability_type,
            vulnerable_lines=vulnerable_lines,
            explanation=remediations["explanation"],
            secure_code=remediations["secure_code"],
            why_it_works=remediations["why_it_works"],
            cwe_id=cls.CWE_MAPPINGS.get(vulnerability_type),
            cve_references=cls.CVE_REFERENCES.get(vulnerability_type),
            owasp_category=cls.OWASP_MAPPINGS.get(vulnerability_type),
        )

    @staticmethod
    def _find_vulnerable_lines(code_snippet: str, vuln_type: VulnerabilityType) -> list[int]:
        # Find line numbers that likely contain the vulnerability
        lines = code_snippet.split("\n")
        vulnerable = []

        # Simple patterns for now
        simple_patterns = {
            VulnerabilityType.SQL_INJECTION: ["select", "union", "insert", "update", "delete"],
            VulnerabilityType.PATH_TRAVERSAL: ["../", "..\\", "path"],
            VulnerabilityType.XSS: ["script", "innerHTML", "document.write"],
            VulnerabilityType.COMMAND_INJECTION: ["system", "exec", "eval", "popen"],
        }

        if vuln_type not in simple_patterns:
            return [1]

        for idx, line in enumerate(lines, start=1):
            for pattern in simple_patterns[vuln_type]:
                if pattern.lower() in line.lower():
                    vulnerable.append(idx)
                    break

        return vulnerable if vulnerable else [1]
