import { useState, useEffect } from "react";
import { motion, useAnimation } from "framer-motion";
import { 
  AlertTriangle, 
  AlertCircle, 
  CheckCircle, 
  Shield, 
  TrendingUp, 
  TrendingDown,
  Zap,
  Activity,
  BarChart3,
  Sparkles,
  Target,
  Clock,
  RefreshCw,
  Eye,
  ChevronRight
} from "lucide-react";
import type { ScanResponse } from "../types";
import './ScoreCard.css';

interface Props {
  result: ScanResponse | null;
  showDetails?: boolean;
  onViewDetails?: () => void;
  onRefresh?: () => void;
  animated?: boolean;
}

const SEVERITY_CONFIG: Record<string, { 
  label: string; 
  color: string; 
  bg: string;
  icon: JSX.Element;
  gradient: string;
  description: string;
}> = {
  critical: { 
    label: "CRITICAL", 
    color: "#ef4444", 
    bg: "rgba(239, 68, 68, 0.15)",
    icon: <AlertTriangle size={24} />,
    gradient: "from-red-600 to-orange-500",
    description: "Immediate action required"
  },
  high: { 
    label: "HIGH", 
    color: "#f97316", 
    bg: "rgba(249, 115, 22, 0.15)",
    icon: <AlertCircle size={24} />,
    gradient: "from-orange-500 to-amber-500",
    description: "Urgent attention needed"
  },
  medium: { 
    label: "MEDIUM", 
    color: "#f59e0b", 
    bg: "rgba(245, 158, 11, 0.15)",
    icon: <Activity size={24} />,
    gradient: "from-yellow-500 to-amber-500",
    description: "Monitor and address"
  },
  low: { 
    label: "LOW", 
    color: "#3b82f6", 
    bg: "rgba(59, 130, 246, 0.15)",
    icon: <Shield size={24} />,
    gradient: "from-blue-500 to-cyan-500",
    description: "Low priority risk"
  },
  safe: { 
    label: "SAFE", 
    color: "#10b981", 
    bg: "rgba(16, 185, 129, 0.15)",
    icon: <CheckCircle size={24} />,
    gradient: "from-green-500 to-emerald-500",
    description: "No immediate threats"
  }
};

export function ScoreCard({ 
  result, 
  showDetails = true,
  onViewDetails,
  onRefresh,
  animated = true 
}: Props) {
  const [isHovered, setIsHovered] = useState(false);
  const [previousScore, setPreviousScore] = useState<number | null>(null);
  const [showScoreAnimation, setShowScoreAnimation] = useState(false);
  const controls = useAnimation();
  const severityConfig = result ? SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.safe : SEVERITY_CONFIG.safe;
  
  useEffect(() => {
    if (result) {
      setShowScoreAnimation(true);
      const timer = setTimeout(() => setShowScoreAnimation(false), 1000);
      return () => clearTimeout(timer);
    }
  }, [result]);

  useEffect(() => {
    if (animated && result) {
      controls.start({
        scale: [1, 1.02, 1],
        transition: { duration: 0.5 }
      });
    }
  }, [result, animated, controls]);

  const probability = result ? Math.round(result.probability * 100) : 0;
  const anomalyScore = result ? result.anomaly_score : 0;
  const threatScore = result ? Math.min(100, Math.round(probability * anomalyScore * 10)) : 0;
  
  const getRiskLevel = (score: number) => {
    if (score >= 90) return "Critical";
    if (score >= 70) return "High";
    if (score >= 50) return "Medium";
    if (score >= 30) return "Low";
    return "Safe";
  };

  const getTrendDirection = () => {
    if (!result || !previousScore) return null;
    const currentScore = probability * anomalyScore * 10;
    return currentScore > previousScore ? "up" : "down";
  };

  const formatAnomalyScore = (score: number) => {
    if (score > 0.9) return "Very High";
    if (score > 0.7) return "High";
    if (score > 0.5) return "Medium";
    if (score > 0.3) return "Low";
    return "Normal";
  };

  const getConfidenceLevel = () => {
    if (!result) return "Unknown";
    if (result.probability > 0.9) return "High";
    if (result.probability > 0.7) return "Medium";
    return "Low";
  };

  if (!result) {
    return (
      <motion.div 
        className="score-card empty"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        whileHover={{ scale: 1.02 }}
      >
        <div className="card-glow" />
        <div className="card-content">
          <div className="empty-state">
            <div className="empty-icon">
              <Target size={48} />
            </div>
            <div className="empty-text">
              <h3>Awaiting Scan Results</h3>
              <p>Run a security scan to see live risk scoring, anomaly detection, and remediation insights</p>
            </div>
          </div>
          <div className="quick-stats">
            <div className="stat">
              <span className="stat-label">Real-time Analysis</span>
              <span className="stat-value">Ready</span>
            </div>
            <div className="stat">
              <span className="stat-label">Threat Intel</span>
              <span className="stat-value">Live</span>
            </div>
            <div className="stat">
              <span className="stat-label">Model Confidence</span>
              <span className="stat-value">98.5%</span>
            </div>
          </div>
        </div>
      </motion.div>
    );
  }

  const trendDirection = getTrendDirection();
  const riskLevel = getRiskLevel(threatScore);

  return (
    <motion.div 
      className="score-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
      style={{ borderColor: severityConfig.color }}
    >
      {/* Background Glow Effect */}
      <div className="card-glow" style={{ background: `radial-gradient(circle at center, ${severityConfig.color}20 0%, transparent 70%)` }} />
      
      {/* Animated Score Update */}
      {showScoreAnimation && (
        <motion.div 
          className="score-update-animation"
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 2, opacity: 0 }}
        >
          <Sparkles size={24} />
        </motion.div>
      )}

      {/* Card Header */}
      <div className="card-header">
        <div className="header-content">
          <div 
            className="severity-icon"
            style={{ 
              background: severityConfig.bg,
              color: severityConfig.color
            }}
          >
            {severityConfig.icon}
          </div>
          <div className="header-text">
            <span className="eyebrow">Risk Assessment</span>
            <h2 className="severity-label" style={{ color: severityConfig.color }}>
              {severityConfig.label}
            </h2>
            <span className="risk-description">{severityConfig.description}</span>
          </div>
        </div>
        
        <div className="header-actions">
          {onRefresh && (
            <button className="action-btn refresh" onClick={onRefresh}>
              <RefreshCw size={16} />
            </button>
          )}
          {onViewDetails && (
            <button className="action-btn details" onClick={onViewDetails}>
              <Eye size={16} />
              <span>Details</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Score */}
      <div className="score-display">
        <div className="score-circle">
          <svg width="140" height="140" viewBox="0 0 140 140">
            <circle 
              cx="70" 
              cy="70" 
              r="64" 
              fill="none" 
              stroke="rgba(255, 255, 255, 0.1)" 
              strokeWidth="8" 
            />
            <circle 
              cx="70" 
              cy="70" 
              r="64" 
              fill="none" 
              stroke={severityConfig.color}
              strokeWidth="8" 
              strokeLinecap="round"
              strokeDasharray={`${probability * 3.77} 377`}
              transform="rotate(-90 70 70)"
            />
          </svg>
          <div className="score-content">
            <div className="score-value">{probability}%</div>
            <div className="score-label">Vulnerability Probability</div>
          </div>
        </div>

        {/* Score Metrics */}
        <div className="score-metrics">
          <div className="metric-card">
            <div className="metric-header">
              <Zap size={16} />
              <span>Threat Score</span>
              {trendDirection && (
                <div className={`trend-indicator ${trendDirection}`}>
                  {trendDirection === 'up' ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
                </div>
              )}
            </div>
            <div className="metric-value">{threatScore}</div>
            <div className="metric-bar">
              <motion.div 
                className="metric-fill"
                initial={{ width: 0 }}
                animate={{ width: `${threatScore}%` }}
                transition={{ duration: 1, delay: 0.2 }}
                style={{ background: severityConfig.color }}
              />
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <Activity size={16} />
              <span>Anomaly Detection</span>
            </div>
            <div className="metric-value">{anomalyScore.toFixed(2)}</div>
            <div className="metric-label">{formatAnomalyScore(anomalyScore)}</div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <Shield size={16} />
              <span>Confidence</span>
            </div>
            <div className="metric-value">{getConfidenceLevel()}</div>
            <div className="metric-label">{(result.probability * 100).toFixed(1)}% certain</div>
          </div>
        </div>
      </div>

      {/* Risk Breakdown */}
      <div className="risk-breakdown">
        <div className="breakdown-header">
          <BarChart3 size={18} />
          <span>Risk Breakdown</span>
        </div>
        <div className="breakdown-grid">
          <div className="breakdown-item">
            <span className="item-label">Severity Level</span>
            <span 
              className="item-value"
              style={{ color: severityConfig.color }}
            >
              {riskLevel}
            </span>
          </div>
          <div className="breakdown-item">
            <span className="item-label">CVSS Score</span>
            <span className="item-value">{result.cvss_score?.toFixed(1) || 'N/A'}</span>
          </div>
          <div className="breakdown-item">
            <span className="item-label">Attack Complexity</span>
            <span className="item-value">
              {anomalyScore > 0.7 ? 'High' : anomalyScore > 0.4 ? 'Medium' : 'Low'}
            </span>
          </div>
          <div className="breakdown-item">
            <span className="item-label">Impact Scope</span>
            <span className="item-value">
              {result.severity === 'critical' ? 'System-wide' : 'Limited'}
            </span>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions">
        <button className="action-btn primary">
          <AlertTriangle size={16} />
          <span>Create Incident</span>
        </button>
        <button className="action-btn secondary">
          <Target size={16} />
          <span>Remediation Plan</span>
        </button>
        <button className="action-btn outline">
          <Clock size={16} />
          <span>Schedule Scan</span>
        </button>
      </div>

      {/* Footer Stats */}
      <div className="footer-stats">
        <div className="footer-stat">
          <span className="stat-label">Scan Time</span>
          <span className="stat-value">
            {new Date(result.timestamp).toLocaleTimeString([], { 
              hour: '2-digit', 
              minute: '2-digit' 
            })}
          </span>
        </div>
        <div className="footer-stat">
          <span className="stat-label">Model Version</span>
          <span className="stat-value">v2.4.1</span>
        </div>
        <div className="footer-stat">
          <span className="stat-label">Recommendations</span>
          <span className="stat-value">
            {result.suggestions?.length || 0}
            <ChevronRight size={12} />
          </span>
        </div>
      </div>

      {/* Hover Details */}
      {isHovered && showDetails && (
        <motion.div 
          className="hover-details"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 10 }}
        >
          <div className="details-content">
            <h4>Detailed Insights</h4>
            <p>Risk analysis based on {result.suggestions?.length || 0} vulnerability indicators</p>
            <div className="insights-grid">
              <div className="insight">
                <div className="insight-dot" style={{ background: severityConfig.color }} />
                <span>Anomaly detection triggered {probability > 70 ? 'multiple' : 'limited'} times</span>
              </div>
              <div className="insight">
                <div className="insight-dot" style={{ background: severityConfig.color }} />
                <span>Confidence level supports {getConfidenceLevel().toLowerCase()} reliability</span>
              </div>
              <div className="insight">
                <div className="insight-dot" style={{ background: severityConfig.color }} />
                <span>Recommend automated remediation for {probability > 50 ? 'immediate' : 'scheduled'} action</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}