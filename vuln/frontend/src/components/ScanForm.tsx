import { FormEvent, useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import type { ScanRequest } from "../types";
import { 
  Zap, 
  Shield, 
  AlertCircle, 
  Code, 
  Globe, 
  Cpu,
  BookOpen,
  Sparkles,
  // Send,  // Not available in lucide-react
  Loader2,
  ChevronRight,
  Copy,
  // Check,  // Not available in lucide-react
  Terminal,
  FileCode,
  Lock,
  Database,
  // Unlock,  // Not available in lucide-react
  // Wand2  // Not available in lucide-react
} from "lucide-react";
import { classifyAttack, remediateCode } from "../api/client";
import './ScanForm.css';

interface Props {
  loading: boolean;
  onSubmit: (payload: ScanRequest) => void;
  onShowHistory: () => void;
  onQuickScan?: () => void;
}

const FRAMEWORKS = [
  { id: "react", name: "React", icon: "⚛️", color: "#61dafb" },
  { id: "vue", name: "Vue.js", icon: "🟢", color: "#42b883" },
  { id: "angular", name: "Angular", icon: "🅰️", color: "#dd0031" },
  { id: "nextjs", name: "Next.js", icon: "▲", color: "#000000" },
  { id: "express", name: "Express", icon: "⚡", color: "#68a063" },
  { id: "django", name: "Django", icon: "🐍", color: "#092e20" },
  { id: "spring", name: "Spring", icon: "🌱", color: "#6db33f" },
  { id: "laravel", name: "Laravel", icon: "🔥", color: "#ff2d20" },
  { id: "rails", name: "Rails", icon: "💎", color: "#cc0000" },
  { id: "flask", name: "Flask", icon: "⚗️", color: "#000000" },
];

const PAYLOAD_TEMPLATES = [
  { 
    name: "SQL Injection", 
    value: "id=1' OR '1'='1' --", 
    description: "Basic SQL injection payload",
    icon: <DatabaseIcon />
  },
  { 
    name: "XSS", 
    value: "<script>alert('xss')</script>", 
    description: "Cross-site scripting attack",
    icon: <AlertTriangleIcon />
  },
  { 
    name: "Command Injection", 
    value: "| cat /etc/passwd", 
    description: "OS command injection",
    icon: <TerminalIcon />
  },
  { 
    name: "Path Traversal", 
    value: "../../../etc/passwd", 
    description: "Directory traversal attack",
    icon: <FolderTreeIcon />
  },
  { 
    name: "JWT Token", 
    value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", 
    description: "JWT token manipulation",
    icon: <LockIcon />
  },
];

// Utility Icons
function DatabaseIcon() { return <Database size={16} />; }
function AlertTriangleIcon() { return <AlertCircle size={16} />; }
function TerminalIcon() { return <Terminal size={16} />; }
function FolderTreeIcon() { return <FileCode size={16} />; }
function LockIcon() { return <Lock size={16} />; }

export function ScanForm({ loading, onSubmit, onShowHistory, onQuickScan }: Props) {
  const [url, setUrl] = useState("https://api.example.com/v1/users");
  const [payload, setPayload] = useState("id=1' OR '1'='1' --");
  const [selectedFramework, setSelectedFramework] = useState("react");
  const [notes, setNotes] = useState("Suspicious user input detected during authentication flow");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copied, setCopied] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [remediation, setRemediation] = useState<string | null>(null);
  const [attackType, setAttackType] = useState<string | null>(null);

  useEffect(() => {
    if (copied) {
      const timer = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timer);
    }
  }, [copied]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
  };

  const analyzePayload = async () => {
    if (!payload.trim()) return;
    
    setAnalyzing(true);
    try {
      const result = await classifyAttack(payload);
      setAttackType(result.type);
      
      const remediated = await remediateCode(payload, selectedFramework);
      setRemediation(remediated.code);
    } catch (error) {
      console.error("Analysis failed:", error);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setValidationError(null);
    setAttackType(null);
    setRemediation(null);

    // Validate URL
    if (!url.trim()) {
      setValidationError("Endpoint URL is required");
      return;
    }

    if (!isValidUrl(url)) {
      setValidationError("Please enter a valid URL (e.g., https://example.com)");
      return;
    }

    // Validate payload
    if (!payload.trim()) {
      setValidationError("Payload is required for analysis");
      return;
    }

    // Submit the scan
    onSubmit({ 
      url, 
      payload, 
      metadata: { 
        framework: selectedFramework,
        notes,
        attackType: attackType || "unknown"
      } 
    });
  };

  const isValidUrl = (urlString: string): boolean => {
    try {
      new URL(urlString);
      return true;
    } catch {
      return false;
    }
  };

  const selectTemplate = (template: typeof PAYLOAD_TEMPLATES[0]) => {
    setPayload(template.value);
    setValidationError(null);
  };

  const getFramework = (id: string) => {
    return FRAMEWORKS.find(f => f.id === id) || FRAMEWORKS[0];
  };

  return (
    <motion.div 
      className="scan-form-container"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <div className="form-header">
        <div className="header-icon">
          <Shield className="header-icon-svg" />
        </div>
        <div>
          <h2 className="form-title">Live Security Scanner</h2>
          <p className="form-subtitle">Analyze endpoints and payloads for security vulnerabilities</p>
        </div>
      </div>

      {/* Main Form */}
      <form className="scan-form" onSubmit={handleSubmit}>
        {/* URL Input */}
        <div className="input-group">
          <div className="input-header">
            <Globe size={18} />
            <span>Target Endpoint</span>
            <div className="input-badge">
              <Lock size={14} />
              <span>HTTPS Required</span>
            </div>
          </div>
          <div className="input-wrapper">
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setValidationError(null);
              }}
              placeholder="https://api.example.com/v1/users"
              className="url-input"
              required
              aria-label="Endpoint URL"
            />
            <div className="input-actions">
              <button 
                type="button" 
                className="action-btn"
                onClick={() => copyToClipboard(url)}
                title="Copy URL"
              >
                {copied ? <Copy size={14} /> : <Copy size={14} />}
              </button>
            </div>
          </div>
          <div className="input-hint">
            Enter the complete endpoint URL including protocol (HTTPS)
          </div>
        </div>

        {/* Payload Input with Templates */}
        <div className="input-group">
          <div className="input-header">
            <Code size={18} />
            <span>Attack Payload</span>
            <button 
              type="button"
              className="analyze-btn"
              onClick={analyzePayload}
              disabled={analyzing || !payload.trim()}
            >
              {analyzing ? <Loader2 size={14} className="spin" /> : <Sparkles size={14} />}
              <span>Analyze</span>
            </button>
          </div>
          
          {/* Payload Templates */}
          <div className="templates-grid">
            {PAYLOAD_TEMPLATES.map((template) => (
              <motion.button
                key={template.name}
                type="button"
                className={`template-card ${payload === template.value ? 'active' : ''}`}
                onClick={() => selectTemplate(template)}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <div className="template-icon">{template.icon}</div>
                <div className="template-content">
                  <div className="template-name">{template.name}</div>
                  <div className="template-desc">{template.description}</div>
                </div>
              </motion.button>
            ))}
          </div>

          <div className="input-wrapper">
            <textarea
              value={payload}
              onChange={(e) => {
                setPayload(e.target.value);
                setValidationError(null);
                setAttackType(null);
                setRemediation(null);
              }}
              rows={4}
              className="payload-textarea"
              required
              aria-label="Payload"
              placeholder="Enter malicious payload for security analysis..."
            />
            <div className="textarea-actions">
              <button 
                type="button" 
                className="action-btn"
                onClick={() => copyToClipboard(payload)}
                title="Copy Payload"
              >
                {copied ? <Copy size={14} /> : <Copy size={14} />}
              </button>
            </div>
          </div>
        </div>

        {/* Framework Selection */}
        <div className="input-group">
          <div className="input-header">
            <Cpu size={18} />
            <span>Application Framework</span>
          </div>
          <div className="framework-grid">
            {FRAMEWORKS.map((framework) => {
              const isSelected = selectedFramework === framework.id;
              return (
                <motion.button
                  key={framework.id}
                  type="button"
                  className={`framework-chip ${isSelected ? 'selected' : ''}`}
                  onClick={() => setSelectedFramework(framework.id)}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  style={{ 
                    '--framework-color': framework.color,
                  } as React.CSSProperties}
                >
                  <span className="framework-icon">{framework.icon}</span>
                  <span className="framework-name">{framework.name}</span>
                  {isSelected && (
                    <motion.div 
                      className="selection-indicator"
                      layoutId="framework-selection"
                    />
                  )}
                </motion.button>
              );
            })}
          </div>
        </div>

        {/* Advanced Options */}
        <div className="advanced-toggle">
          <button 
            type="button"
            className="toggle-btn"
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <ChevronRight className={`toggle-icon ${showAdvanced ? 'open' : ''}`} />
            <span>Advanced Options</span>
          </button>
          
          <AnimatePresence>
            {showAdvanced && (
              <motion.div 
                className="advanced-options"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
              >
                <div className="input-group">
                  <div className="input-header">
                    <BookOpen size={18} />
                    <span>Analyst Notes</span>
                  </div>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={3}
                    className="notes-textarea"
                    placeholder="Add context, observations, or special instructions..."
                    aria-label="Analyst Notes"
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Analysis Results */}
        {(attackType || remediation) && (
          <motion.div 
            className="analysis-results"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            {attackType && (
              <div className="result-card">
                <div className="result-header">
                  <AlertCircle size={20} />
                  <span>Attack Classification</span>
                </div>
                <div className="result-content">
                  <div className="attack-type">{attackType}</div>
                  <div className="attack-severity">High Severity</div>
                </div>
              </div>
            )}
            
            {remediation && (
              <div className="result-card">
                <div className="result-header">
                  {/* <Wand2 size={20} /> */}
                  <span>Suggested Remediation</span>
                </div>
                <div className="result-content">
                  <pre className="remediation-code">{remediation}</pre>
                  <button 
                    type="button"
                    className="copy-code-btn"
                    onClick={() => copyToClipboard(remediation)}
                  >
                    <Copy size={14} />
                    <span>Copy Code</span>
                  </button>
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* Validation Error */}
        <AnimatePresence>
          {validationError && (
            <motion.div 
              className="validation-error"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
            >
              <AlertCircle size={20} />
              <span>{validationError}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Form Actions */}
        <div className="form-actions">
          <button 
            type="submit" 
            className="scan-btn"
            disabled={loading}
          >
            {loading ? (
              <>
                <Loader2 size={20} className="spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Zap size={20} />
                <span>Execute Security Scan</span>
              </>
            )}
          </button>
          
          <div className="secondary-actions">
            <button 
              type="button" 
              className="ghost-btn"
              onClick={onShowHistory}
            >
              <BookOpen size={16} />
              <span>View History</span>
            </button>
            
            {onQuickScan && (
              <button 
                type="button" 
                className="outline-btn"
                onClick={onQuickScan}
              >
                {/* <Send size={16} /> */}
                <span>Quick Scan</span>
              </button>
            )}
          </div>
        </div>

        {/* Security Tips */}
        <div className="security-tips">
          <div className="tips-header">
            <Shield size={16} />
            <span>Security Best Practices</span>
          </div>
          <div className="tips-grid">
            <div className="tip">
              <div className="tip-icon">🔒</div>
              <div className="tip-content">Always validate and sanitize user input</div>
            </div>
            <div className="tip">
              <div className="tip-icon">🛡️</div>
              <div className="tip-content">Use parameterized queries for databases</div>
            </div>
            <div className="tip">
              <div className="tip-icon">⚡</div>
              <div className="tip-content">Implement rate limiting on APIs</div>
            </div>
            <div className="tip">
              <div className="tip-icon">👁️</div>
              <div className="tip-content">Regular security scanning is essential</div>
            </div>
          </div>
        </div>
      </form>
    </motion.div>
  );
}