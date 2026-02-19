import { useState } from "react";
import { motion } from "framer-motion";
import { AlertCircle, CheckCircle, AlertTriangle } from "lucide-react";
import "../styles/sequential.css";
import { SequentialWorkflowResponse } from "../types";

export function SequentialWorkflow() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<SequentialWorkflowResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [riskState, setRiskState] = useState<"safe" | "suspicious" | "unsafe" | null>(null);
  const [payload, setPayload] = useState("");
  const [step2Loaded, setStep2Loaded] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const getRiskStateColor = (state: string | null) => {
    switch (state?.toLowerCase()) {
      case "safe":
        return "#10b981";
      case "suspicious":
        return "#f59e0b";
      case "unsafe":
        return "#ef4444";
      default:
        return "#6b7280";
    }
  };

  const getRiskStateLabel = (state: string | null) => {
    switch (state?.toLowerCase()) {
      case "safe":
        return "Safe";
      case "suspicious":
        return "Suspicious";
      case "unsafe":
        return "Unsafe";
      default:
        return "Unknown";
    }
  };

  // Utility function to validate URL format
  function isValidUrl(urlString: string): boolean {
    if (!urlString || typeof urlString !== "string" || urlString.trim() === "") {
      return false;
    }
    try {
      new URL(urlString);
      return true;
    } catch {
      return false;
    }
  }

  const handleUrlChange = (value: string) => {
    setUrl(value);
    setRiskState(null);
    setResult(null);
    setStep2Loaded(false);
    setValidationError(null);
  };

  const handleAnalyzeUrl = async () => {
    setValidationError(null);
    setError(null);

    // Validate URL
    if (!url || typeof url !== "string" || url.trim() === "") {
      setValidationError("URL is required. Please enter a valid URL.");
      return;
    }

    if (!isValidUrl(url)) {
      setValidationError("Invalid URL format. Please enter a valid URL (e.g., https://example.com).");
      return;
    }
    
    setLoading(true);
    setResult(null);
    setStep2Loaded(false);

    try {
      const response = await fetch("http://localhost:8006/api/v1/sequential-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, payload: null }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Validate response data
      if (!data || typeof data !== "object" || !data.step1) {
        throw new Error("Invalid response from server: missing step1 data");
      }

      setResult(data);
      
      // Determine risk state from step1 safely
      if (data.step1?.is_safe === true) {
        setRiskState("safe");
      } else if (data.step1?.risk_level_if_unsafe) {
        if (data.step1.risk_level_if_unsafe === "low" || data.step1.risk_level_if_unsafe === "medium") {
          setRiskState("suspicious");
        } else {
          setRiskState("unsafe");
        }
      } else {
        setRiskState("unsafe");
      }
      
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error occurred");
    } finally {
      setLoading(false);
    }
  };

  const handleInjectPayload = async () => {
    setValidationError(null);
    setError(null);

    // Validate payload
    if (!payload || typeof payload !== "string" || payload.trim() === "") {
      setValidationError("Payload is required. Please enter a payload to test.");
      return;
    }
    
    if (!result || !url) {
      setError("No website URL available for payload testing");
      return;
    }
    
    setLoading(true);

    try {
      const response = await fetch("http://localhost:8006/api/v1/sequential-analysis", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, payload }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Validate response
      if (!data || typeof data !== "object") {
        throw new Error("Invalid response from server");
      }

      setResult(data);
      
      // Update risk state with payload results safely
      if (data.step2?.payload_safe === true) {
        setRiskState("safe");
      } else if (data.step2?.combined_risk) {
        if (data.step2.combined_risk === "low" || data.step2.combined_risk === "medium") {
          setRiskState("suspicious");
        } else {
          setRiskState("unsafe");
        }
      } else {
        setRiskState("unsafe");
      }
      
      setStep2Loaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="sequential-workflow">
      <motion.div
        className="conversational-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1>🛡️ Website Security Analysis</h1>
        <p>Let's evaluate your website's security posture</p>
      </motion.div>

      {/* SIMPLE URL INPUT */}
      <motion.div
        className="conversation-block"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <div className="input-section">
          <label>What website would you like to analyze?</label>
          {validationError && (
            <motion.div 
              className="validation-error" 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              style={{ 
                backgroundColor: "#fee", 
                border: "1px solid #fcc", 
                borderRadius: "4px", 
                padding: "12px",
                color: "#c00",
                marginBottom: "16px",
                fontSize: "0.95rem"
              }}
            >
              ⚠️ {validationError}
            </motion.div>
          )}
          <div className="url-input-group">
            <input
              type="text"
              value={url}
              onChange={(e) => handleUrlChange(e.target.value)}
              placeholder="https://example.com/api/endpoint"
              disabled={loading}
              onKeyPress={(e) => e.key === "Enter" && handleAnalyzeUrl()}
              aria-label="Website URL to analyze"
            />
            <button 
              onClick={handleAnalyzeUrl}
              disabled={loading || !url.trim()}
              className="analyze-btn"
            >
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </div>
      </motion.div>

      {error && (
        <motion.div className="error-message" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <AlertCircle size={20} />
          <span>{error}</span>
        </motion.div>
      )}

      {/* RISK STATE DISPLAY & CONDITIONAL FLOWS */}
      {result && result.step1 && (
        <motion.div
          className="results-section"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          {/* Website Risk State */}
          <motion.div
            className="risk-state-block"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            <div className="risk-state-indicator" style={{ borderColor: getRiskStateColor(riskState) }}>
              <div className="risk-state-icon">
                {riskState === "safe" && <CheckCircle size={32} color="#10b981" />}
                {riskState === "suspicious" && <AlertTriangle size={32} color="#f59e0b" />}
                {riskState === "unsafe" && <AlertCircle size={32} color="#ef4444" />}
              </div>
              <div className="risk-state-content">
                <div className="risk-state-label">Website Risk State</div>
                <div className="risk-state-value" style={{ color: getRiskStateColor(riskState) }}>
                  {getRiskStateLabel(riskState)}
                </div>
              </div>
            </div>
          </motion.div>

          {/* SAFE WEBSITE - SHOW ATTACK INJECTION */}
          {riskState === "safe" && !step2Loaded && (
            <motion.div
              className="conversation-block"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="message-content">
                <h3>✅ This website appears to be secure</h3>
                <p>{result.step1?.explanation ?? 'Website appears secure'}</p>
                
                <div className="next-step">
                  <p><strong>Next:</strong> Let's test if it can be compromised by injecting an attack payload.</p>
                  
                  <div className="attack-injection-section">
                    <label>Try injecting an attack payload:</label>
                    {validationError && (
                      <motion.div 
                        className="validation-error" 
                        initial={{ opacity: 0 }} 
                        animate={{ opacity: 1 }}
                        style={{ 
                          backgroundColor: "#fee", 
                          border: "1px solid #fcc", 
                          borderRadius: "4px", 
                          padding: "12px",
                          color: "#c00",
                          marginBottom: "16px",
                          fontSize: "0.95rem"
                        }}
                      >
                        ⚠️ {validationError}
                      </motion.div>
                    )}
                    <textarea
                      value={payload}
                      onChange={(e) => {
                        setPayload(e.target.value);
                        setValidationError(null);
                      }}
                      placeholder="E.g., id=1' OR '1'='1  or <script>alert('xss')</script>"
                      rows={2}
                      disabled={loading}
                      aria-label="Attack payload to test"
                    />
                    <button 
                      onClick={handleInjectPayload}
                      disabled={loading || !payload.trim()}
                      className="inject-btn"
                    >
                      {loading ? "Testing..." : "Test Attack"}
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* UNSAFE WEBSITE - SHOW VULNERABILITIES */}
          {(riskState === "unsafe" || riskState === "suspicious") && !step2Loaded && (
            <motion.div
              className="conversation-block warning"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="message-content">
                <h3>⚠️ Security concerns detected</h3>
                <p>{result.step1?.explanation ?? 'Security concerns detected'}</p>

                {Array.isArray(result.step1?.vulnerability_locations) && result.step1.vulnerability_locations.length > 0 && (
                  <div className="exposed-areas">
                    <strong>Exposed areas:</strong>
                    <ul>
                      {result.step1.vulnerability_locations.map((loc, idx) => (
                        <li key={idx}>{typeof loc === 'string' ? loc.replace(/_/g, " ") : 'Unknown location'}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {Array.isArray(result.step1?.indicators) && result.step1.indicators.length > 0 && (
                  <div className="detected-issues">
                    <strong>Issues detected:</strong>
                    <div className="issues-list">
                      {result.step1.indicators.map((ind, idx) => (
                        <div key={idx} className="issue-item">
                          <span className="issue-type">{ind?.indicator_type ?? 'Unknown'}:</span>
                          <span className="issue-desc">{ind?.description ?? 'No description'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {Array.isArray(result.step1?.remediation_steps) && result.step1.remediation_steps.length > 0 && (
                  <div className="what-to-fix">
                    <strong>What needs to be fixed:</strong>
                    <div className="fixes-list">
                      {result.step1.remediation_steps.map((step, idx) => (
                        <div key={idx} className="fix-item">
                          <div className="fix-title">{step?.title ?? 'Fix'}</div>
                          <div className="fix-description">{step?.description ?? 'No description'}</div>
                          <div className="fix-code">
                            <code>{step?.code_example ?? 'No code example'}</code>
                          </div>
                          <div className="fix-reference">Reference: {step?.reference ?? 'Unknown'}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 2 PAYLOAD INJECTION RESULTS */}
          {step2Loaded && result.step2 && (
            <motion.div
              className="conversation-block payload-result"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="message-content">
                <h3>Attack Test Results</h3>
                
                <div className="attack-summary">
                  <p><strong>Attack attempted:</strong> {Array.isArray(result.step2?.attack_vectors_detected) ? result.step2.attack_vectors_detected.join(", ") || "Unknown" : "Unknown"}</p>
                  <p><strong>Outcome:</strong> {result.step2?.payload_safe ? "Blocked" : "Detected as dangerous"}</p>
                </div>

                <p>{result.step2?.explanation ?? 'No explanation available'}</p>

                {Array.isArray(result.step2?.attack_vectors_detected) && result.step2.attack_vectors_detected.length > 0 && (
                  <div className="attack-vectors-section">
                    <strong>Attack types that could work:</strong>
                    <ul>
                      {result.step2.attack_vectors_detected.map((vector, idx) => (
                        <li key={idx}>{vector ?? 'Unknown vector'}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {Array.isArray(result.step2?.remediation_steps) && result.step2.remediation_steps.length > 0 && (
                  <div className="fix-guidance">
                    <strong>Recommended fixes:</strong>
                    <div className="fixes-list">
                      {result.step2.remediation_steps.map((step, idx) => (
                        <div key={idx} className="fix-item">
                          <div className="fix-title">{step?.title ?? 'Fix'}</div>
                          <div className="fix-description">{step?.description ?? 'No description'}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="next-action">
                  <button 
                    onClick={() => {
                      setUrl("");
                      setPayload("");
                      setResult(null);
                      setRiskState(null);
                      setStep2Loaded(false);
                      setValidationError(null);
                      setError(null);
                    }}
                    className="reset-btn"
                  >
                    Analyze Another Website
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {/* STEP 3 - RISK EVALUATION */}
          {result.step3 && (
            <motion.div
              className="conversation-block"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <div className="message-content">
                <h3>📊 Risk Assessment</h3>
                <p>{result.step3?.justification ?? 'Risk assessment unavailable'}</p>

                {Array.isArray(result.step3?.contributing_factors) && result.step3.contributing_factors.length > 0 && (
                  <div className="factors-list">
                    <strong>Contributing factors:</strong>
                    <ul>
                      {result.step3.contributing_factors.map((factor, idx) => (
                        <li key={idx}>{factor ?? 'Unknown factor'}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 4 - GUIDANCE */}
          {result.step4 && (
            <motion.div
              className="conversation-block"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <div className="message-content">
                <h3>💡 Security Guidance</h3>
                <p>{result.step4?.detailed_explanation ?? 'Guidance unavailable'}</p>

                {Array.isArray(result.step4?.vulnerable_areas) && result.step4.vulnerable_areas.length > 0 && (
                  <div className="vulnerable-areas">
                    <strong>Areas to focus on:</strong>
                    <ul>
                      {result.step4.vulnerable_areas.map((area, idx) => (
                        <li key={idx}>{area ?? 'Unknown area'}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {Array.isArray(result.step4?.best_practices) && result.step4.best_practices.length > 0 && (
                  <div className="best-practices">
                    <strong>Security best practices:</strong>
                    <ul>
                      {result.step4.best_practices.map((practice, idx) => (
                        <li key={idx}>{practice ?? 'Unknown practice'}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 5 - REMEDIATION */}
          {result.step5 && (
            <motion.div
              className="conversation-block"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
            >
              <div className="message-content">
                <h3>🛠️ Action Plan</h3>
                <p>{result.step5?.summary ?? 'Action plan unavailable'}</p>

                {Array.isArray(result.step5?.priority_remediations) && result.step5.priority_remediations.length > 0 && (
                  <div className="priority-items">
                    <strong>Priority fixes:</strong>
                    <div className="fixes-list">
                      {result.step5.priority_remediations.map((step, idx) => (
                        <div key={idx} className="fix-item">
                          <div className="fix-title">{step?.title ?? 'Fix'}</div>
                          <div className="fix-description">{step?.description ?? 'No description'}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {Array.isArray(result.step5?.short_term_actions) && result.step5.short_term_actions.length > 0 && (
                  <div className="immediate-actions">
                    <strong>Immediate actions:</strong>
                    <ul>
                      {result.step5.short_term_actions.map((action, idx) => (
                        <li key={idx}>{action ?? 'Unknown action'}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {Array.isArray(result.step5?.long_term_strategy) && result.step5.long_term_strategy.length > 0 && (
                  <div className="long-term">
                    <strong>Long-term strategy (6-12 months):</strong>
                    <ul>
                      {result.step5.long_term_strategy.map((strategy, idx) => (
                        <li key={idx}>{strategy ?? 'Unknown strategy'}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {Array.isArray(result.step5?.compliance_requirements) && result.step5.compliance_requirements.length > 0 && (
                  <div className="compliance">
                    <strong>Compliance requirements:</strong>
                    <ul>
                      {result.step5.compliance_requirements.map((requirement, idx) => (
                        <li key={idx}>{requirement ?? 'Unknown requirement'}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </motion.div>
      )}
    </div>
  );
}
