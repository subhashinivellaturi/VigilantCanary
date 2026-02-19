import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertCircle, 
  CheckCircle, 
  AlertTriangle,
  Shield,
  Zap,
  Activity,
  BarChart3,
  Clock,
  Eye,
  Filter,
  Download,
  RefreshCw,
  TrendingUp,
  Cpu,
  Database,
  Globe,
  Lock,
  // Unlock,  // Not in lucide-react
  Search,
  Sparkles
} from "lucide-react";
import './ProfessionalDashboard.css';

interface ScanResult {
  id: string;
  timestamp: string;
  endpoint: string;
  framework: string;
  riskState: "safe" | "unsafe";
  anomalyScore: number;
  vulnerabilityProbability: number;
  severity: "low" | "medium" | "high" | "critical";
  vulnerabilities: string[];
  cvss_score?: number | null;
  responseTime?: number;
  threatLevel: number;
}

interface DashboardProps {
  datasetCount: number;
  currentAccuracy: number;
  result?: ScanResult | null;
}

const FRAMEWORKS = [
  { value: "express", label: "Express.js", icon: "⚡", color: "#68a063" },
  { value: "django", label: "Django", icon: "🐍", color: "#092e20" },
  { value: "spring", label: "Spring Boot", icon: "🌱", color: "#6db33f" },
  { value: "laravel", label: "Laravel", icon: "🔥", color: "#ff2d20" },
  { value: "aspnet", label: "ASP.NET", icon: "🟦", color: "#512bd4" },
  { value: "rails", label: "Ruby on Rails", icon: "💎", color: "#cc0000" },
  { value: "flask", label: "Flask", icon: "⚗️", color: "#000000" },
];

const STATS_CARDS = [
  { id: 1, label: "Total Scans", value: "1,247", change: "+12%", icon: <Activity />, color: "#3b82f6" },
  { id: 2, label: "Threats Detected", value: "42", change: "-5%", icon: <AlertTriangle />, color: "#ef4444" },
  { id: 3, label: "Avg Response Time", value: "24ms", change: "-3ms", icon: <Zap />, color: "#10b981" },
  { id: 4, label: "Model Accuracy", value: "96.8%", change: "+2.3%", icon: <Cpu />, color: "#8b5cf6" },
];

export function ProfessionalDashboard({ datasetCount, currentAccuracy }: DashboardProps) {
  const [formData, setFormData] = useState({
    endpoint: "",
    payload: "",
    framework: "",
    analystNotes: "",
  });
  const [loading, setLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([
    {
      id: "1",
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      endpoint: "https://api.example.com/v1/users",
      framework: "express",
      riskState: "unsafe",
      anomalyScore: 85.2,
      vulnerabilityProbability: 92.5,
      severity: "critical",
      vulnerabilities: ["SQL Injection", "CORS Misconfiguration"],
      cvss_score: 9.8,
      responseTime: 245,
      threatLevel: 95,
    },
    {
      id: "2",
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      endpoint: "https://admin.example.com/login",
      framework: "django",
      riskState: "safe",
      anomalyScore: 12.4,
      vulnerabilityProbability: 15.2,
      severity: "low",
      vulnerabilities: ["Weak Password Policy"],
      cvss_score: 3.2,
      responseTime: 120,
      threatLevel: 25,
    }
  ]);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"quick" | "advanced">("quick");
  const [selectedFilter, setSelectedFilter] = useState<string>("all");
  const [scanStats, setScanStats] = useState({
    safe: results.filter(r => r.riskState === "safe").length,
    unsafe: results.filter(r => r.riskState === "unsafe").length,
    critical: results.filter(r => r.severity === "critical").length,
  });

  const modelConfidence = Math.min(95 + Math.random() * 4, 99.9);

  const simulateScanProgress = () => {
    setScanProgress(0);
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + Math.random() * 10;
      });
    }, 200);
    return interval;
  };

  const handleInputChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleRunScan = async () => {
    if (!formData.endpoint.trim()) {
      setError("Endpoint URL is required");
      return;
    }

    setLoading(true);
    setError(null);
    const progressInterval = simulateScanProgress();

    try {
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      const riskState: "safe" | "unsafe" = Math.random() > 0.5 ? "unsafe" : "safe";
      const anomalyScore = riskState === "unsafe" ? 60 + Math.random() * 40 : Math.random() * 30;
      const vulnProb = riskState === "unsafe" ? 70 + Math.random() * 30 : Math.random() * 30;
      
      const severities: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];
      const severity = riskState === "unsafe" 
        ? severities[Math.floor(Math.random() * 3) + 1] 
        : "low";

      const newResult: ScanResult = {
        id: Date.now().toString(),
        timestamp: new Date().toISOString(),
        endpoint: formData.endpoint,
        framework: formData.framework,
        riskState,
        anomalyScore,
        vulnerabilityProbability: vulnProb,
        severity,
        vulnerabilities: riskState === "unsafe" 
          ? ["Potential SQL Injection", "XSS Vulnerability", "CORS Misconfiguration"].slice(0, Math.floor(Math.random() * 3) + 1)
          : ["No critical vulnerabilities found"],
        cvss_score: riskState === "unsafe" ? 4 + Math.random() * 6 : null,
        responseTime: Math.floor(Math.random() * 500),
        threatLevel: Math.floor(anomalyScore),
      };

      setCurrentResult(newResult);
      setResults((prev) => [newResult, ...prev]);
      setScanStats(prev => ({
        ...prev,
        [riskState]: prev[riskState] + 1,
        critical: riskState === "unsafe" && severity === "critical" ? prev.critical + 1 : prev.critical
      }));
      setFormData({ endpoint: "", payload: "", framework: "", analystNotes: "" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => {
        setLoading(false);
        setScanProgress(0);
      }, 500);
    }
  };

  const getRiskColor = (state: string) => {
    switch (state) {
      case "safe":
        return "#10b981";
      case "unsafe":
        return "#ef4444";
      default:
        return "#6b7280";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low": return "#10b981";
      case "medium": return "#f59e0b";
      case "high": return "#f97316";
      case "critical": return "#ef4444";
      default: return "#6b7280";
    }
  };

  const getFrameworkIcon = (framework: string) => {
    return FRAMEWORKS.find(f => f.value === framework)?.icon || "🌐";
  };

  const exportResults = () => {
    const data = {
      scanResults: results,
      summary: scanStats,
      timestamp: new Date().toISOString()
    };
    
    const dataStr = JSON.stringify(data, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `security-scan-report-${Date.now()}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const filteredResults = selectedFilter === "all" 
    ? results 
    : results.filter(r => r.severity === selectedFilter || r.riskState === selectedFilter);

  return (
    <div className="professional-dashboard">
      {/* Header Section */}
      <motion.div 
        className="dashboard-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <Shield className="header-icon-svg" />
          </div>
          <div>
            <h1 className="header-title">Vigilant Canary</h1>
            <p className="header-subtitle">AI-Powered Security Intelligence Platform</p>
          </div>
        </div>
        <div className="header-stats">
          <div className="model-confidence">
            <div className="confidence-label">Model Confidence</div>
            <div className="confidence-value">{modelConfidence.toFixed(2)}%</div>
            <div className="confidence-note">{datasetCount.toLocaleString()} attack traces analyzed</div>
          </div>
        </div>
      </motion.div>

      {/* Stats Overview */}
      <div className="stats-grid">
        {STATS_CARDS.map((stat, index) => (
          <motion.div
            key={stat.id}
            className="stat-card"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            whileHover={{ y: -5, transition: { duration: 0.2 } }}
          >
            <div className="stat-icon" style={{ color: stat.color }}>
              {stat.icon}
            </div>
            <div className="stat-content">
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.label}</div>
            </div>
            <div className={`stat-change ${stat.change.startsWith('+') ? 'positive' : 'negative'}`}>
              {stat.change}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="dashboard-grid">
        {/* Left Panel - Scanner */}
        <motion.div
          className="scanner-panel"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="panel-header">
            <div className="panel-title">
              <Search className="panel-icon" />
              <span>Live Security Scanner</span>
            </div>
            <div className="panel-actions">
              <button className="view-toggle">
                <Filter size={16} />
                <span>Filter</span>
              </button>
              <button className="view-toggle" onClick={() => setViewMode(viewMode === "quick" ? "advanced" : "quick")}>
                {viewMode === "quick" ? "Advanced" : "Simple"}
              </button>
            </div>
          </div>

          <div className="scanner-form">
            <div className="form-section">
              <div className="input-group floating">
                <Globe className="input-icon" />
                <input
                  type="text"
                  value={formData.endpoint}
                  onChange={(e) => handleInputChange("endpoint", e.target.value)}
                  placeholder="https://example.com/api/endpoint"
                  disabled={loading}
                  className="endpoint-input"
                />
                <label>Target Endpoint *</label>
              </div>

              {viewMode === "advanced" && (
                <motion.div
                  className="input-group"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                >
                  <label>
                    <Activity size={16} />
                    Payload / Attack Vector
                  </label>
                  <textarea
                    value={formData.payload}
                    onChange={(e) => handleInputChange("payload", e.target.value)}
                    placeholder="Enter malicious payload for testing (SQLi, XSS, etc.)"
                    rows={3}
                    disabled={loading}
                    className="payload-textarea"
                  />
                </motion.div>
              )}

              <div className="input-group">
                <label>
                  <Cpu size={16} />
                  Application Framework
                </label>
                <div className="framework-chips">
                  {FRAMEWORKS.map((fw) => (
                    <button
                      key={fw.value}
                      className={`framework-chip ${formData.framework === fw.value ? "selected" : ""}`}
                      onClick={() => handleInputChange("framework", fw.value)}
                      style={{ '--fw-color': fw.color } as any}
                    >
                      <span className="fw-icon">{fw.icon}</span>
                      <span className="fw-label">{fw.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="input-group">
                <label>
                  <AlertCircle size={16} />
                  Analyst Notes
                </label>
                <textarea
                  value={formData.analystNotes}
                  onChange={(e) => handleInputChange("analystNotes", e.target.value)}
                  placeholder="Add context, special instructions, or observed behavior..."
                  rows={2}
                  disabled={loading}
                />
              </div>
            </div>

            {error && (
              <motion.div 
                className="error-alert"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
              >
                <AlertCircle size={18} />
                <span>{error}</span>
              </motion.div>
            )}

            <div className="scan-action">
              <button
                onClick={handleRunScan}
                disabled={loading || !formData.endpoint.trim()}
                className="scan-btn"
              >
                {loading ? (
                  <>
                    <div className="scan-spinner" />
                    <span>Scanning... {Math.round(scanProgress)}%</span>
                  </>
                ) : (
                  <>
                    <Zap size={18} />
                    <span>Execute Security Scan</span>
                  </>
                )}
              </button>
              
              {loading && (
                <div className="scan-progress">
                  <div className="progress-bar">
                    <motion.div 
                      className="progress-fill"
                      initial={{ width: "0%" }}
                      animate={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </motion.div>

        {/* Right Panel - Current Result */}
        <motion.div
          className="results-panel"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="panel-header">
            <div className="panel-title">
              <BarChart3 className="panel-icon" />
              <span>Scan Results</span>
            </div>
            {currentResult && (
              <button className="export-btn" onClick={exportResults}>
                <Download size={16} />
                <span>Export</span>
              </button>
            )}
          </div>

          <AnimatePresence mode="wait">
            {currentResult ? (
              <motion.div
                key="result"
                className="current-result"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
              >
                {/* Risk State */}
                <div className="risk-state-card" style={{ borderColor: getRiskColor(currentResult.riskState) }}>
                  <div className="risk-icon">
                    {currentResult.riskState === "safe" ? <Lock size={32} /> : <Lock size={32} />}
                  </div>
                  <div className="risk-content">
                    <div className="risk-label">Security Status</div>
                    <div 
                      className="risk-value"
                      style={{ color: getRiskColor(currentResult.riskState) }}
                    >
                      {currentResult.riskState === "safe" ? "SECURE" : "VULNERABLE"}
                    </div>
                    <div className="risk-endpoint">{currentResult.endpoint}</div>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="metrics-grid">
                  <div className="metric-card">
                    <div className="metric-header">
                      <span className="metric-label">Anomaly Score</span>
                      <span className="metric-trend">
                        <TrendingUp size={12} />
                        High
                      </span>
                    </div>
                    <div className="metric-value">{currentResult.anomalyScore.toFixed(1)}</div>
                    <div className="metric-bar">
                      <motion.div 
                        className="metric-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${currentResult.anomalyScore}%` }}
                        transition={{ duration: 1 }}
                        style={{ background: getSeverityColor(currentResult.severity) }}
                      />
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-header">
                      <span className="metric-label">Threat Level</span>
                      <span className="metric-trend critical">Critical</span>
                    </div>
                    <div className="metric-value">{currentResult.threatLevel}%</div>
                    <div className="metric-bar">
                      <motion.div 
                        className="metric-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${currentResult.threatLevel}%` }}
                        transition={{ duration: 1, delay: 0.2 }}
                        style={{ background: getRiskColor(currentResult.riskState) }}
                      />
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-header">
                      <span className="metric-label">Response Time</span>
                      <span className="metric-trend positive">Fast</span>
                    </div>
                    <div className="metric-value">{currentResult.responseTime}ms</div>
                    <div className="metric-bar">
                      <motion.div 
                        className="metric-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(100, currentResult.responseTime || 0 / 5)}%` }}
                        transition={{ duration: 1, delay: 0.4 }}
                        style={{ background: "#3b82f6" }}
                      />
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities */}
                {currentResult.vulnerabilities.length > 0 && (
                  <div className="vulnerabilities-section">
                    <div className="section-header">
                      <AlertTriangle size={20} />
                      <span>Detected Vulnerabilities</span>
                    </div>
                    <div className="vulnerabilities-list">
                      {currentResult.vulnerabilities.map((vuln, idx) => (
                        <motion.div
                          key={idx}
                          className="vulnerability-item"
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: idx * 0.1 }}
                        >
                          <div className="vuln-severity" style={{ background: getSeverityColor(currentResult.severity) }} />
                          <span className="vuln-title">{vuln}</span>
                          {currentResult.cvss_score && (
                            <div className="cvss-badge">CVSS: {currentResult.cvss_score.toFixed(1)}</div>
                          )}
                        </motion.div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                className="empty-state"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <div className="empty-icon">
                  <Sparkles size={48} />
                </div>
                <h3>No Scan Results</h3>
                <p>Run a security scan to see detailed results here</p>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Bottom Panel - Scan History */}
        <motion.div
          className="history-panel"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="panel-header">
            <div className="panel-title">
              <Clock className="panel-icon" />
              <span>Scan History</span>
              <span className="history-count">{results.length} total</span>
            </div>
            <div className="history-filters">
              <button 
                className={`filter-btn ${selectedFilter === "all" ? "active" : ""}`}
                onClick={() => setSelectedFilter("all")}
              >
                All
              </button>
              <button 
                className={`filter-btn ${selectedFilter === "critical" ? "active" : ""}`}
                onClick={() => setSelectedFilter("critical")}
              >
                Critical
              </button>
              <button 
                className={`filter-btn ${selectedFilter === "unsafe" ? "active" : ""}`}
                onClick={() => setSelectedFilter("unsafe")}
              >
                Unsafe
              </button>
            </div>
          </div>

          <div className="history-list">
            <AnimatePresence>
              {filteredResults.map((scan) => (
                <motion.div
                  key={scan.id}
                  className="history-card"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  layout
                  whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
                >
                  <div className="card-header">
                    <div className="endpoint-info">
                      <div className="endpoint-url">{scan.endpoint}</div>
                      <div className="endpoint-meta">
                        <span className="framework-tag">
                          {getFrameworkIcon(scan.framework)} {scan.framework}
                        </span>
                        <span className="timestamp">
                          <Clock size={12} />
                          {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </div>
                    <div className="severity-badge" style={{ 
                      backgroundColor: `${getSeverityColor(scan.severity)}20`,
                      color: getSeverityColor(scan.severity)
                    }}>
                      {scan.severity.toUpperCase()}
                    </div>
                  </div>

                  <div className="card-metrics">
                    <div className="metric-chip">
                      <span className="chip-label">Anomaly</span>
                      <span className="chip-value">{scan.anomalyScore.toFixed(1)}</span>
                    </div>
                    <div className="metric-chip">
                      <span className="chip-label">Threat</span>
                      <span className="chip-value">{scan.threatLevel}%</span>
                    </div>
                    <div className="metric-chip">
                      <span className="chip-label">Response</span>
                      <span className="chip-value">{scan.responseTime}ms</span>
                    </div>
                  </div>

                  <div className="card-status">
                    <div className={`status-indicator ${scan.riskState}`}>
                      <div className="status-dot" style={{ background: getRiskColor(scan.riskState) }} />
                      <span>{scan.riskState.toUpperCase()}</span>
                    </div>
                    <button className="view-details">
                      <Eye size={14} />
                      Details
                    </button>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>

            {filteredResults.length === 0 && (
              <div className="empty-history">
                <div className="empty-icon">
                  <Database size={32} />
                </div>
                <p>No scan results match the selected filter</p>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  );
}