import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertCircle, 
  CheckCircle, 
  AlertTriangle, 
  Shield, 
  Zap, 
  Filter, 
  Download,
  Eye,
  ChevronDown,
  ChevronUp,
  BarChart3,
  Activity,
  Clock,
  Database,
  Code,
  Lock,
  Unlock,
  ExternalLink,
  Copy,
  Check,
  Sparkles,
  TrendingUp,
  // ShieldAlert,
  FileText
} from "lucide-react";
import './ScanResultsPanel.css';

interface Indicator {
  indicator_type: string;
  severity_factor: number;
  confidence: number;
  description: string;
  http_method?: string;
  affected_parameter?: string;
  response_status_code?: number;
  cwe_id?: string;
  remediation?: string;
}

interface ScanResponse {
  scan_timestamp: string;
  step1: {
    is_safe: boolean;
    indicators: Indicator[];
    explanation: string;
    risk_level_if_unsafe: string;
  };
  step2?: {
    payload_safe: boolean;
    indicators: Indicator[];
    explanation: string;
  };
  disclaimer: string;
  scan_id?: string;
}

interface ScanResultsPanelProps {
  data: ScanResponse | null;
  url: string;
  onExport?: (format: 'json' | 'pdf' | 'csv') => void;
  onShare?: () => void;
}

type VulnerabilityFilter = "All" | "XSS" | "SQLi" | "CSRF" | "Path Traversal" | "Command Injection" | "Security Headers" | "Crypto" | "Auth";

const VULNERABILITY_TYPE_MAP: Record<string, string> = {
  xss: "XSS",
  sql_injection: "SQLi",
  csrf: "CSRF",
  path_traversal: "Path Traversal",
  command_injection: "Command Injection",
  missing_security_headers: "Security Headers",
  open_directory: "Open Directory",
  insecure_http: "Insecure HTTP",
  weak_crypto: "Crypto",
  auth_bypass: "Auth",
  cwe_89: "SQLi",
  cwe_79: "XSS",
};

const SEVERITY_CONFIG: Record<string, { 
  label: string; 
  bg: string; 
  text: string; 
  border: string;
  icon: JSX.Element;
}> = {
  critical: { 
    label: "Critical", 
    bg: "rgba(239, 68, 68, 0.15)", 
    text: "#ef4444", 
    border: "rgba(239, 68, 68, 0.3)",
    icon: <AlertTriangle size={16} />
  },
  high: { 
    label: "High", 
    bg: "rgba(249, 115, 22, 0.15)", 
    text: "#f97316", 
    border: "rgba(249, 115, 22, 0.3)",
    icon: <AlertCircle size={16} />
  },
  medium: { 
    label: "Medium", 
    bg: "rgba(245, 158, 11, 0.15)", 
    text: "#f59e0b", 
    border: "rgba(245, 158, 11, 0.3)",
    icon: <Activity size={16} />
  },
  low: { 
    label: "Low", 
    bg: "rgba(59, 130, 246, 0.15)", 
    text: "#3b82f6", 
    border: "rgba(59, 130, 246, 0.3)",
    icon: <Shield size={16} />
  },
};

const BADGE_CONFIG: Record<string, { color: string; icon: JSX.Element }> = {
  XSS: { color: "#ef4444", icon: <Code size={14} /> },
  SQLi: { color: "#f59e0b", icon: <Database size={14} /> },
  CSRF: { color: "#8b5cf6", icon: <ShieldAlert size={14} /> },
  "Path Traversal": { color: "#06b6d4", icon: <FileText size={14} /> },
  "Command Injection": { color: "#ec4899", icon: <TerminalIcon /> },
  "Security Headers": { color: "#6366f1", icon: <Lock size={14} /> },
  "Open Directory": { color: "#f97316", icon: <FolderIcon /> },
  Crypto: { color: "#10b981", icon: <Lock size={14} /> },
  Auth: { color: "#8b5cf6", icon: <Unlock size={14} /> },
  Default: { color: "#94a3b8", icon: <AlertCircle size={14} /> }
};

function TerminalIcon() { return <Code size={14} />; }
function FolderIcon() { return <FileText size={14} />; }

export function ScanResultsPanel({ data, url, onExport, onShare }: ScanResultsPanelProps) {
  const [filter, setFilter] = useState<VulnerabilityFilter>("All");
  const [showDisclaimer, setShowDisclaimer] = useState(true);
  const [expandedIndicator, setExpandedIndicator] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'list' | 'grid'>('list');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const allIndicators = useMemo(() => {
    const indicators: Indicator[] = [];
    if (data?.step1?.indicators) {
      indicators.push(...data.step1.indicators.map((ind, idx) => ({
        ...ind,
        id: `step1-${idx}`,
        step: 1
      })));
    }
    if (data?.step2?.indicators) {
      indicators.push(...data.step2.indicators.map((ind, idx) => ({
        ...ind,
        id: `step2-${idx}`,
        step: 2
      })));
    }
    return indicators;
  }, [data]);

  const getSeverityLevel = (factor: number) => {
    if (factor >= 0.85) return "critical";
    if (factor >= 0.70) return "high";
    if (factor >= 0.50) return "medium";
    return "low";
  };

  const filteredIndicators = useMemo(() => {
    let filtered = allIndicators;

    // Filter by vulnerability type
    if (filter !== "All") {
      filtered = filtered.filter((ind) => {
        const mappedType = VULNERABILITY_TYPE_MAP[ind.indicator_type] || ind.indicator_type;
        return mappedType === filter;
      });
    }

    // Filter by severity
    if (selectedSeverity !== 'all') {
      filtered = filtered.filter((ind) => 
        getSeverityLevel(ind.severity_factor) === selectedSeverity
      );
    }

    return filtered;
  }, [allIndicators, filter, selectedSeverity]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    allIndicators.forEach((ind) => {
      const level = getSeverityLevel(ind.severity_factor);
      counts[level as keyof typeof counts]++;
    });
    
    return counts;
  }, [allIndicators]);

  const indicatorsByType = useMemo(() => {
    const grouped: Record<string, Indicator[]> = {};
    
    allIndicators.forEach((ind) => {
      const type = VULNERABILITY_TYPE_MAP[ind.indicator_type] || ind.indicator_type;
      if (!grouped[type]) {
        grouped[type] = [];
      }
      grouped[type].push(ind);
    });
    
    return grouped;
  }, [allIndicators]);

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getRiskScore = () => {
    if (allIndicators.length === 0) return 100;
    
    const totalSeverity = allIndicators.reduce((sum, ind) => sum + ind.severity_factor, 0);
    const avgSeverity = totalSeverity / allIndicators.length;
    return Math.max(0, 100 - (avgSeverity * 100));
  };

  const formatTimestamp = (isoString: string) => {
    try {
      const date = new Date(isoString);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      
      if (diffMins < 1) return "Just now";
      if (diffMins < 60) return `${diffMins}m ago`;
      
      return date.toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit',
        day: 'numeric',
        month: 'short'
      });
    } catch {
      return isoString;
    }
  };

  const getVulnerabilityType = (indicatorType: string) => {
    return VULNERABILITY_TYPE_MAP[indicatorType] || indicatorType;
  };

  const getBadgeConfig = (type: string) => {
    return BADGE_CONFIG[type] || BADGE_CONFIG.Default;
  };

  if (!data) return null;

  const isOverallSafe = data.step1.is_safe && (!data.step2 || data.step2.payload_safe);
  const riskScore = getRiskScore();

  return (
    <div className="scan-results-container">
      {/* Header */}
      <motion.div 
        className="results-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <Shield className="header-icon-svg" />
          </div>
          <div>
            <h2 className="header-title">Security Scan Results</h2>
            <p className="header-subtitle">
              Comprehensive vulnerability analysis for {url}
            </p>
          </div>
        </div>
        <div className="header-actions">
          <div className="scan-id">
            <Clock size={14} />
            <span>Scan ID: {data.scan_id || 'N/A'}</span>
          </div>
          <button className="export-btn" onClick={() => onExport?.('pdf')}>
            <Download size={16} />
            <span>Export</span>
          </button>
        </div>
      </motion.div>

      {/* Risk Overview */}
      <div className="risk-overview">
        <div className="risk-score-card">
          <div className="score-circle">
            <svg width="120" height="120" viewBox="0 0 120 120">
              <circle 
                cx="60" 
                cy="60" 
                r="54" 
                fill="none" 
                stroke="rgba(255, 255, 255, 0.1)" 
                strokeWidth="8" 
              />
              <circle 
                cx="60" 
                cy="60" 
                r="54" 
                fill="none" 
                stroke={isOverallSafe ? "#10b981" : "#ef4444"}
                strokeWidth="8" 
                strokeLinecap="round"
                strokeDasharray={`${riskScore * 3.4} 340`}
                transform="rotate(-90 60 60)"
              />
            </svg>
            <div className="score-content">
              <div className="score-value">{riskScore.toFixed(0)}</div>
              <div className="score-label">Risk Score</div>
            </div>
          </div>
          <div className="risk-status">
            <div className={`status-badge ${isOverallSafe ? 'safe' : 'unsafe'}`}>
              {isOverallSafe ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
              <span>{isOverallSafe ? 'SECURE' : 'VULNERABLE'}</span>
            </div>
            <div className="risk-meta">
              <span>{allIndicators.length} vulnerabilities detected</span>
              <span>Scan time: {formatTimestamp(data.scan_timestamp)}</span>
            </div>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="severity-breakdown">
          <h3 className="breakdown-title">Severity Breakdown</h3>
          <div className="severity-bars">
            {Object.entries(severityCounts).map(([level, count]) => {
              const config = SEVERITY_CONFIG[level];
              const percentage = (count / allIndicators.length) * 100 || 0;
              
              return (
                <div key={level} className="severity-bar">
                  <div className="bar-header">
                    <div className="bar-label">
                      {config.icon}
                      <span>{config.label}</span>
                    </div>
                    <span className="bar-count">{count}</span>
                  </div>
                  <div className="bar-track">
                    <motion.div 
                      className="bar-fill"
                      initial={{ width: 0 }}
                      animate={{ width: `${percentage}%` }}
                      transition={{ duration: 1, delay: 0.2 }}
                      style={{ background: config.text }}
                    />
                  </div>
                  <span className="bar-percentage">{percentage.toFixed(1)}%</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="filters-bar">
        <div className="filter-group">
          <Filter size={16} />
          <span>Filter by:</span>
          <div className="type-filters">
            {Object.keys(BADGE_CONFIG).map((type) => (
              <button
                key={type}
                className={`type-filter ${filter === type ? 'active' : ''}`}
                onClick={() => setFilter(type as VulnerabilityFilter)}
                style={{
                  backgroundColor: filter === type ? BADGE_CONFIG[type]?.color + '20' : 'transparent',
                  borderColor: BADGE_CONFIG[type]?.color
                }}
              >
                <span className="filter-icon">{BADGE_CONFIG[type]?.icon}</span>
                <span>{type}</span>
                <span className="filter-count">
                  {(indicatorsByType[type] || []).length}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="filter-group">
          <span>Severity:</span>
          <div className="severity-filters">
            <button
              className={`severity-filter ${selectedSeverity === 'all' ? 'active' : ''}`}
              onClick={() => setSelectedSeverity('all')}
            >
              All
            </button>
            {Object.entries(SEVERITY_CONFIG).map(([level, config]) => (
              <button
                key={level}
                className={`severity-filter ${selectedSeverity === level ? 'active' : ''}`}
                onClick={() => setSelectedSeverity(level)}
                style={{
                  backgroundColor: selectedSeverity === level ? config.bg : 'transparent',
                  borderColor: config.border,
                  color: selectedSeverity === level ? config.text : 'var(--text-secondary)'
                }}
              >
                {config.icon}
                <span>{config.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="view-controls">
          <button 
            className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
            onClick={() => setViewMode('list')}
          >
            <BarChart3 size={16} />
          </button>
          <button 
            className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
            onClick={() => setViewMode('grid')}
          >
            <Activity size={16} />
          </button>
        </div>
      </div>

      {/* Results Content */}
      <div className="results-content">
        {allIndicators.length === 0 ? (
          <motion.div 
            className="empty-results"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            <div className="empty-icon">
              <CheckCircle size={48} />
            </div>
            <h3>No Security Issues Found</h3>
            <p>The endpoint passed all security checks successfully</p>
            <div className="security-score">
              <Sparkles size={20} />
              <span>Security Score: 100/100</span>
            </div>
          </motion.div>
        ) : filteredIndicators.length === 0 ? (
          <div className="no-match">
            <Filter size={32} />
            <h3>No matching vulnerabilities</h3>
            <p>Try adjusting your filters</p>
          </div>
        ) : viewMode === 'list' ? (
          <div className="vulnerabilities-list">
            <AnimatePresence>
              {filteredIndicators.map((indicator) => {
                const severity = getSeverityLevel(indicator.severity_factor);
                const config = SEVERITY_CONFIG[severity];
                const vulnType = getVulnerabilityType(indicator.indicator_type);
                const badgeConfig = getBadgeConfig(vulnType);
                const isExpanded = expandedIndicator === indicator.id;

                return (
                  <motion.div
                    key={indicator.id}
                    className="vulnerability-card"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    layout
                    onClick={() => setExpandedIndicator(isExpanded ? null : indicator.id)}
                  >
                    <div className="card-header">
                      <div className="vuln-type">
                        <div 
                          className="type-badge"
                          style={{ 
                            backgroundColor: `${badgeConfig.color}20`,
                            color: badgeConfig.color,
                            borderColor: badgeConfig.color
                          }}
                        >
                          {badgeConfig.icon}
                          <span>{vulnType}</span>
                        </div>
                        {indicator.cwe_id && (
                          <div className="cwe-badge">
                            <span>CWE-{indicator.cwe_id}</span>
                          </div>
                        )}
                      </div>

                      <div className="severity-indicator">
                        <div 
                          className="severity-badge"
                          style={{ 
                            backgroundColor: config.bg,
                            color: config.text,
                            borderColor: config.border
                          }}
                        >
                          {config.icon}
                          <span>{config.label}</span>
                        </div>
                      </div>
                    </div>

                    <div className="card-body">
                      <p className="vuln-description">{indicator.description}</p>
                      
                      <div className="vuln-metrics">
                        <div className="metric">
                          <span className="metric-label">Severity</span>
                          <div className="metric-value">
                            <div className="severity-bar">
                              <div 
                                className="severity-fill"
                                style={{ 
                                  width: `${indicator.severity_factor * 100}%`,
                                  background: config.text
                                }}
                              />
                            </div>
                            <span>{(indicator.severity_factor * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                        
                        <div className="metric">
                          <span className="metric-label">Confidence</span>
                          <div className="metric-value">
                            <div className="confidence-meter">
                              <div 
                                className="confidence-fill"
                                style={{ 
                                  width: `${indicator.confidence * 100}%`,
                                  background: indicator.confidence > 0.8 ? '#10b981' : '#f59e0b'
                                }}
                              />
                            </div>
                            <span>{(indicator.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </div>

                        {indicator.http_method && (
                          <div className="metric">
                            <span className="metric-label">Method</span>
                            <span className="metric-value code">{indicator.http_method}</span>
                          </div>
                        )}

                        {indicator.affected_parameter && (
                          <div className="metric">
                            <span className="metric-label">Parameter</span>
                            <span className="metric-value code">{indicator.affected_parameter}</span>
                          </div>
                        )}
                      </div>

                      <motion.div 
                        className="expand-icon"
                        animate={{ rotate: isExpanded ? 180 : 0 }}
                      >
                        <ChevronDown size={20} />
                      </motion.div>
                    </div>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          className="card-details"
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                        >
                          <div className="details-grid">
                            {indicator.response_status_code && (
                              <div className="detail-item">
                                <span className="detail-label">Status Code</span>
                                <span className="detail-value">{indicator.response_status_code}</span>
                              </div>
                            )}
                            
                            {indicator.remediation && (
                              <div className="detail-item full-width">
                                <span className="detail-label">Remediation</span>
                                <span className="detail-value">{indicator.remediation}</span>
                              </div>
                            )}

                            <div className="detail-item full-width">
                              <span className="detail-label">Step</span>
                              <span className="detail-value">Analysis Step {indicator.step}</span>
                            </div>
                          </div>

                          <div className="details-actions">
                            <button 
                              className="action-btn copy"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(indicator.description, indicator.id);
                              }}
                            >
                              {copiedId === indicator.id ? <Check size={14} /> : <Copy size={14} />}
                              <span>Copy Details</span>
                            </button>
                            <button className="action-btn view">
                              <Eye size={14} />
                              <span>View Full Report</span>
                            </button>
                            <button className="action-btn share">
                              <ExternalLink size={14} />
                              <span>Share</span>
                            </button>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        ) : (
          <div className="vulnerabilities-grid">
            {filteredIndicators.map((indicator) => {
              const severity = getSeverityLevel(indicator.severity_factor);
              const config = SEVERITY_CONFIG[severity];
              const vulnType = getVulnerabilityType(indicator.indicator_type);
              const badgeConfig = getBadgeConfig(vulnType);

              return (
                <motion.div
                  key={indicator.id}
                  className="vuln-grid-card"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  whileHover={{ y: -5, transition: { duration: 0.2 } }}
                >
                  <div className="grid-card-header">
                    <div 
                      className="grid-type-badge"
                      style={{ 
                        backgroundColor: `${badgeConfig.color}20`,
                        color: badgeConfig.color,
                        borderColor: badgeConfig.color
                      }}
                    >
                      {badgeConfig.icon}
                      <span>{vulnType}</span>
                    </div>
                    <div 
                      className="grid-severity"
                      style={{ 
                        backgroundColor: config.bg,
                        color: config.text
                      }}
                    >
                      {config.icon}
                    </div>
                  </div>

                  <div className="grid-card-body">
                    <p className="grid-description">{indicator.description}</p>
                    
                    <div className="grid-metrics">
                      <div className="grid-metric">
                        <span className="metric-label">Severity</span>
                        <span className="metric-value">{(indicator.severity_factor * 100).toFixed(0)}%</span>
                      </div>
                      <div className="grid-metric">
                        <span className="metric-label">Confidence</span>
                        <span className="metric-value">{(indicator.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>

                    {indicator.http_method && (
                      <div className="grid-tag">
                        <span>Method: {indicator.http_method}</span>
                      </div>
                    )}
                  </div>

                  <div className="grid-card-footer">
                    <button className="grid-action-btn">
                      <Eye size={14} />
                    </button>
                    <button className="grid-action-btn">
                      <Copy size={14} />
                    </button>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      {/* Detailed Analysis */}
      {data.step1.explanation && (
        <motion.div 
          className="analysis-section"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <h3 className="section-title">
            <FileText size={20} />
            <span>Detailed Analysis</span>
          </h3>
          <div className="analysis-content">
            <pre className="analysis-text">{data.step1.explanation}</pre>
            <div className="analysis-actions">
              <button className="analysis-btn">
                <Download size={16} />
                <span>Download Full Report</span>
              </button>
              <button className="analysis-btn secondary">
                <TrendingUp size={16} />
                <span>View Analytics</span>
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* Disclaimer */}
      <AnimatePresence>
        {showDisclaimer && (
          <motion.div 
            className="disclaimer-section"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
          >
            <div className="disclaimer-header">
              <AlertTriangle size={20} />
              <span>Important Disclaimer</span>
              <button 
                className="close-disclaimer"
                onClick={() => setShowDisclaimer(false)}
              >
                ✕
              </button>
            </div>
            <p className="disclaimer-text">{data.disclaimer}</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Quick Stats */}
      <div className="quick-stats">
        <div className="stat-card">
          <div className="stat-icon">
            <Zap size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{allIndicators.length}</div>
            <div className="stat-label">Total Findings</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Shield size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{Object.keys(indicatorsByType).length}</div>
            <div className="stat-label">Vulnerability Types</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Clock size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{formatTimestamp(data.scan_timestamp)}</div>
            <div className="stat-label">Last Scan</div>
          </div>
        </div>
      </div>
    </div>
  );
}