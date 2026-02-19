import { useState } from "react";
import { motion } from "framer-motion";
import { classifyAttack, remediateCode } from "../api/client";
import type { AttackClassification, RemediationResponse } from "../types";

// Import icons (you'll need to install lucide-react or use your own)
import { 
  AlertTriangle, 
  Shield, 
  Code2, 
  ExternalLink, 
  CheckCircle, 
  XCircle,
  Info,
  Loader2,
  Bug,
  FileCode,
  Lock,
  Zap
} from "lucide-react";

interface Props {
  customUrl?: string;
  customPayload?: string;
}

export function AttackDetector({ customUrl, customPayload }: Props) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AttackClassification | null>(null);
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Helper function to extract parameter names from URL
  const extractParamNames = (urlString: string): string[] => {
    try {
      const url = new URL(urlString);
      return Array.from(url.searchParams.keys());
    } catch {
      return [];
    }
  };

  // Helper function to infer code snippet from URL, payload and attack type
  const generateCodeSnippet = (
    urlString: string,
    payloadString: string,
    attackType: "xss" | "command" | "sqli" | "traversal"
  ): string => {
    try {
      const url = new URL(urlString);
      const params = extractParamNames(urlString);
      const paramName = params.length > 0 ? params[0] : "input";
      const safePayload = payloadString ? payloadString.replace(/`/g, "\\`") : "";

      if (attackType === "xss") {
        return `const ${paramName} = req.query.${paramName};\n// payload example: ${safePayload}\nres.send('<div>' + ${paramName} + '</div>');`;
      } else if (attackType === "sqli") {
        return `const ${paramName} = req.query.${paramName};\n// payload example: ${safePayload}\nconst q = ` +
          "`SELECT * FROM users WHERE id = ${" + paramName + "}`;" +
          "\n// Unsafe execution follows\ndb.query(q);`".replace(/`\$/g, "`$");
      } else if (attackType === "command") {
        return `const ${paramName} = req.query.${paramName};\n// payload example: ${safePayload}\nconst out = exec(${paramName});`;
      } else if (attackType === "traversal") {
        return `const ${paramName} = req.query.${paramName};\n// payload example: ${safePayload}\nfs.readFile('./uploads/' + ${paramName}, (err, data) => { res.send(data); });`;
      }
    } catch (e) {
      if (attackType === "xss") return `res.send('<div>' + ${JSON.stringify(payloadString)} + '</div>');`;
      if (attackType === "sqli") return `// payload: ${JSON.stringify(payloadString)}\ndb.query("SELECT ... " + payload);`;
      if (attackType === "command") return `// payload: ${JSON.stringify(payloadString)}\nexec(payload);`;
      if (attackType === "traversal") return `// payload: ${JSON.stringify(payloadString)}\nfs.readFile(payload, ...)`;
    }
    return "";
  };

  // Get severity color based on attack type and confidence
  const getSeverityColor = (attackType: string, confidence: number) => {
    const type = attackType?.toLowerCase() || "";
    if (confidence > 0.8) return "var(--critical)";
    if (confidence > 0.6) return "var(--high)";
    if (confidence > 0.4) return "var(--medium)";
    return "var(--low)";
  };

  // Get severity icon
  const getSeverityIcon = (attackType: string, confidence: number) => {
    if (confidence > 0.8) return <AlertTriangle size={20} />;
    if (confidence > 0.6) return <Shield size={20} />;
    return <Info size={20} />;
  };

  // Run detection
  const runDetection = async () => {
    setLoading(true);
    setRemediationLoading(true);
    setError(null);
    setResult(null);
    setRemediation(null);

    try {
      const url = customUrl || "https://example.com/comment";
      const payload = customPayload || "comment=<script>alert('XSS Attack')</script>";

      const classification = await classifyAttack(url, payload);
      setResult(classification);

      const rawType = (classification.attack_type || "").toLowerCase();
      let normalized: "xss" | "command" | "sqli" | "traversal" = "xss";
      let vulnerabilityType = "xss";

      if (rawType.includes("xss")) {
        normalized = "xss";
        vulnerabilityType = "xss";
      } else if (rawType.includes("sql")) {
        normalized = "sqli";
        vulnerabilityType = "sql_injection";
      } else if (rawType.includes("command") || rawType.includes("cmd")) {
        normalized = "command";
        vulnerabilityType = "command_injection";
      } else if (rawType.includes("travers") || rawType.includes("path")) {
        normalized = "traversal";
        vulnerabilityType = "path_traversal";
      } else {
        normalized = "xss";
        vulnerabilityType = classification.attack_type || "xss";
      }

      const codeSnippet = generateCodeSnippet(url, payload, normalized);
      const language = url.includes(".py") ? "python" : "javascript";

      try {
        const remediationResult = await remediateCode(
          codeSnippet,
          vulnerabilityType,
          language,
          url,
          payload
        );
        setRemediation(remediationResult);
      } catch (remediationErr) {
        console.error("Remediation fetch failed:", remediationErr);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setRemediationLoading(false);
    }
  };

  return (
    <motion.div
      className="attack-detector-container"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Header Section */}
      <div className="detector-header">
        <div className="header-title">
          <Zap className="header-icon" size={28} />
          <h2>Attack Detection & Analysis</h2>
        </div>
        <p className="header-subtitle">
          Analyze endpoints and payloads for potential security vulnerabilities
        </p>
      </div>

      {/* Input Summary Cards */}
      <div className="input-summary-grid">
        <div className="input-card">
          <div className="input-card-header">
            <ExternalLink size={18} />
            <span>Target Endpoint</span>
          </div>
          <div className="input-card-content">
            <code className="endpoint-url">{customUrl || "No endpoint entered"}</code>
            {customUrl && (
              <button className="copy-btn" onClick={() => navigator.clipboard.writeText(customUrl)}>
                Copy
              </button>
            )}
          </div>
        </div>

        <div className="input-card">
          <div className="input-card-header">
            <Bug size={18} />
            <span>Test Payload</span>
          </div>
          <div className="input-card-content">
            <code className="payload-text">{customPayload || "No payload entered"}</code>
            {customPayload && (
              <button className="copy-btn" onClick={() => navigator.clipboard.writeText(customPayload)}>
                Copy
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Action Button */}
      <motion.button
        className="detect-button"
        onClick={runDetection}
        disabled={loading}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
      >
        {loading ? (
          <>
            <Loader2 className="spinner" size={18} />
            Scanning for Attacks...
          </>
        ) : (
          <>
            <Shield size={18} />
            Run Security Analysis
          </>
        )}
      </motion.button>

      {/* Error Display */}
      {error && (
        <motion.div
          className="alert-error"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
        >
          <XCircle size={20} />
          <div>
            <strong>Analysis Failed</strong>
            <p>{error}</p>
          </div>
        </motion.div>
      )}

      {/* Results Section */}
      {result && (
        <motion.div
          className="results-container"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="section-header">
            <h3>
              <Bug size={22} />
              Detection Results
            </h3>
            <div className="result-badge" style={{ 
              backgroundColor: getSeverityColor(result.attack_type, result.confidence || 0)
            }}>
              {getSeverityIcon(result.attack_type, result.confidence || 0)}
              <span>{result.attack_type?.toUpperCase() || 'UNKNOWN'}</span>
              <span className="confidence-score">
                {((result.confidence || 0) * 100).toFixed(0)}%
              </span>
            </div>
          </div>

          {/* Description Card */}
          <div className="result-card">
            <h4>Threat Description</h4>
            <p className="result-description">{result.description || 'No description available'}</p>
          </div>

          {/* Risk Indicators */}
          {Array.isArray(result.risk_indicators) && result.risk_indicators.length > 0 && (
            <div className="result-card">
              <h4>
                <AlertTriangle size={18} />
                Risk Indicators
              </h4>
              <div className="indicators-grid">
                {result.risk_indicators.map((indicator, idx) => (
                  <div key={idx} className="indicator-item">
                    <div className="indicator-dot" />
                    <span>{indicator || 'Unknown indicator'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}

      {/* Remediation Section */}
      {remediation && (
        <motion.div
          className="remediation-container"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="section-header">
            <h3>
              <Lock size={22} />
              Remediation Guide
            </h3>
            <div className="security-badge">
              <CheckCircle size={18} />
              <span>Secure Solution</span>
            </div>
          </div>

          <div className="remediation-grid">
            {/* Vulnerability Info */}
            <div className="remediation-card">
              <h4>Vulnerability Type</h4>
              <div className="vuln-type">
                <FileCode size={16} />
                <span>{remediation.vulnerability_type || 'Unknown'}</span>
              </div>
            </div>

            {/* Explanation */}
            <div className="remediation-card full-width">
              <h4>Security Issue</h4>
              <p className="explanation-text">{remediation.explanation || 'No explanation available'}</p>
            </div>

            {/* Secure Code */}
            <div className="remediation-card full-width">
              <h4>
                <Code2 size={18} />
                Secure Implementation
              </h4>
              <div className="code-container">
                <div className="code-header">
                  <span>Fixed Code</span>
                  <button 
                    className="copy-btn" 
                    onClick={() => navigator.clipboard.writeText(remediation.secure_code || '')}
                  >
                    Copy Code
                  </button>
                </div>
                <pre className="secure-code">
                  <code>{remediation.secure_code || 'No secure code provided'}</code>
                </pre>
              </div>
            </div>

            {/* Why It Works */}
            {remediation.why_it_works && (
              <div className="remediation-card full-width">
                <h4>Why This Fix Works</h4>
                <p className="why-text">{remediation.why_it_works}</p>
              </div>
            )}

            {/* Vulnerable Lines */}
            {Array.isArray(remediation.vulnerable_lines) && remediation.vulnerable_lines.length > 0 && (
              <div className="remediation-card">
                <h4>Vulnerable Lines</h4>
                <div className="vulnerable-lines">
                  {remediation.vulnerable_lines.map((line, idx) => (
                    <span key={idx} className="line-badge">Line {line}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* Loading State for Remediation */}
      {remediationLoading && (
        <motion.div
          className="loading-container"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <Loader2 className="spinner-large" size={32} />
          <p>Generating security recommendations...</p>
        </motion.div>
      )}
    </motion.div>
  );
}