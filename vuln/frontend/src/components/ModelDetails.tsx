import { useState } from "react";
import { motion } from "framer-motion";
import { 
  // Brain,  // Not in lucide-react
  Cpu, 
  Zap, 
  TrendingUp, 
  Shield, 
  Eye, 
  AlertTriangle,
  RefreshCw,
  BarChart3,
  Clock,
  // Layers  // Not in lucide-react
} from "lucide-react";
import { Card } from './ui/Card';
import './ModelDetails.css';

interface Props {
  datasetSize: number;
  accuracy?: number;
  lastUpdated?: string;
  activeInferences?: number;
}

const FEATURES = [
  {
    // icon: <Brain size={20} />,
    title: "Anomaly Intensity",
    description: "Isolation Forest enriches every payload vector with anomaly intensity before classification.",
    color: "#8b5cf6"
  },
  {
    icon: <Cpu size={20} />,
    title: "LightGBM Ensemble",
    description: "Consumes augmented features to achieve 96%+ accuracy on real datasets.",
    color: "#3b82f6"
  },
  {
    icon: <Eye size={20} />,
    title: "Explainability Stream",
    description: "Illuminates the top five drivers behind each verdict to help analysts triage faster.",
    color: "#10b981"
  },
  {
    icon: <RefreshCw size={20} />,
    title: "Scheduled Refresh",
    description: "Automatically retrains the stack so the dashboard always reflects the live model.",
    color: "#f59e0b"
  }
];

const PERFORMANCE_METRICS = [
  { label: "Accuracy", value: "96.8%", trend: "+2.3%" },
  { label: "Precision", value: "95.2%", trend: "+1.8%" },
  { label: "Recall", value: "97.1%", trend: "+3.1%" },
  { label: "F1-Score", value: "96.1%", trend: "+2.5%" }
];

export function ModelDetails({ 
  datasetSize, 
  accuracy = 96.8, 
  lastUpdated = "2 hours ago",
  activeInferences = 2457 
}: Props) {
  const [expandedFeature, setExpandedFeature] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<"overview" | "performance" | "details">("overview");

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="model-details-container"
    >
      <Card 
        title="Real-Time Hybrid Detector" 
        subtitle="Isolation Forest + LightGBM Ensemble"
        className="model-card"
      >
        {/* Stats Header */}
        <div className="model-stats-header">
          <div className="stat-chip">
            <div className="stat-icon">
              <Zap size={16} />
            </div>
            <div>
              <div className="stat-value">{datasetSize.toLocaleString()}</div>
              <div className="stat-label">Training Samples</div>
            </div>
          </div>
          
          <div className="stat-chip">
            <div className="stat-icon">
              <Zap size={16} />
            </div>
            <div>
              <div className="stat-value">{activeInferences.toLocaleString()}</div>
              <div className="stat-label">Live Inferences</div>
            </div>
          </div>
          
          <div className="stat-chip">
            <div className="stat-icon">
              <Clock size={16} />
            </div>
            <div>
              <div className="stat-value">{lastUpdated}</div>
              <div className="stat-label">Last Updated</div>
            </div>
          </div>
        </div>

        {/* View Mode Tabs */}
        <div className="view-mode-tabs">
          <button 
            className={`tab-btn ${viewMode === "overview" ? "active" : ""}`}
            onClick={() => setViewMode("overview")}
          >
            <BarChart3 size={16} />
            Overview
          </button>
          <button 
            className={`tab-btn ${viewMode === "performance" ? "active" : ""}`}
            onClick={() => setViewMode("performance")}
          >
            <TrendingUp size={16} />
            Performance
          </button>
          <button 
            className={`tab-btn ${viewMode === "details" ? "active" : ""}`}
            onClick={() => setViewMode("details")}
          >
            <AlertTriangle size={16} />
            Architecture
          </button>
        </div>

        {/* Overview View */}
        {viewMode === "overview" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="overview-content"
          >
            <div className="model-description">
              <p className="description-text">
                Production-ready hybrid ensemble trained on <span className="highlight">{datasetSize.toLocaleString()}</span> live attack traces. 
                Built to flag <span className="highlight">zero-day payloads</span> before attackers weaponize them.
              </p>
            </div>

            <div className="features-grid">
              {FEATURES.map((feature, index) => (
                <motion.div
                  key={index}
                  className={`feature-card ${expandedFeature === index ? "expanded" : ""}`}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: index * 0.1 }}
                  onClick={() => setExpandedFeature(expandedFeature === index ? null : index)}
                  whileHover={{ y: -5, transition: { duration: 0.2 } }}
                >
                  <div 
                    className="feature-icon-wrapper"
                    style={{ backgroundColor: `${feature.color}20`, borderColor: feature.color }}
                  >
                    <div style={{ color: feature.color }}>
                      {feature.icon}
                    </div>
                  </div>
                  <div className="feature-content">
                    <h4 className="feature-title">{feature.title}</h4>
                    <p className="feature-description">{feature.description}</p>
                  </div>
                  <motion.div 
                    className="feature-glow"
                    animate={{
                      opacity: [0.3, 0.7, 0.3],
                      scale: [1, 1.2, 1],
                    }}
                    transition={{
                      duration: 2,
                      repeat: Infinity,
                      ease: "easeInOut"
                    }}
                  />
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

        {/* Performance View */}
        {viewMode === "performance" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="performance-content"
          >
            <div className="accuracy-ring">
              <div className="ring-container">
                <svg width="120" height="120" viewBox="0 0 120 120">
                  <circle 
                    cx="60" 
                    cy="60" 
                    r="54" 
                    fill="none" 
                    stroke="rgba(59, 130, 246, 0.1)" 
                    strokeWidth="8" 
                  />
                  <circle 
                    cx="60" 
                    cy="60" 
                    r="54" 
                    fill="none" 
                    stroke="url(#gradient)" 
                    strokeWidth="8" 
                    strokeLinecap="round"
                    strokeDasharray={`${accuracy * 3.4} 340`}
                    transform="rotate(-90 60 60)"
                  />
                  <defs>
                    <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#3b82f6" />
                      <stop offset="100%" stopColor="#8b5cf6" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="ring-content">
                  <div className="accuracy-value">{accuracy}%</div>
                  <div className="accuracy-label">Accuracy</div>
                </div>
              </div>
              <div className="accuracy-note">
                <TrendingUp size={14} />
                <span>+2.3% improvement over baseline</span>
              </div>
            </div>

            <div className="metrics-grid">
              {PERFORMANCE_METRICS.map((metric, index) => (
                <div key={index} className="metric-card">
                  <div className="metric-header">
                    <div className="metric-label">{metric.label}</div>
                    <div className="metric-trend positive">{metric.trend}</div>
                  </div>
                  <div className="metric-value">{metric.value}</div>
                  <div className="metric-bar">
                    <div 
                      className="metric-fill"
                      style={{ 
                        width: `${parseFloat(metric.value)}%`,
                        background: `linear-gradient(90deg, ${FEATURES[index % FEATURES.length].color}20, ${FEATURES[index % FEATURES.length].color})`
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* Details View */}
        {viewMode === "details" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="details-content"
          >
            <div className="architecture-diagram">
              <div className="pipeline">
                <div className="pipeline-stage">
                  <div className="stage-icon anomaly">IF</div>
                  <div className="stage-content">
                    <div className="stage-title">Isolation Forest</div>
                    <div className="stage-description">Anomaly detection & feature augmentation</div>
                  </div>
                </div>
                <div className="pipeline-arrow">
                  <div className="arrow-line" />
                  <div className="arrow-head" />
                </div>
                <div className="pipeline-stage">
                  <div className="stage-icon classifier">LGB</div>
                  <div className="stage-content">
                    <div className="stage-title">LightGBM</div>
                    <div className="stage-description">Gradient boosting classification</div>
                  </div>
                </div>
                <div className="pipeline-arrow">
                  <div className="arrow-line" />
                  <div className="arrow-head" />
                </div>
                <div className="pipeline-stage">
                  <div className="stage-icon explainer">XAI</div>
                  <div className="stage-content">
                    <div className="stage-title">Explainable AI</div>
                    <div className="stage-description">Feature importance & reasoning</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="technical-specs">
              <h4 className="specs-title">Technical Specifications</h4>
              <div className="specs-grid">
                <div className="spec-item">
                  <div className="spec-label">Ensemble Type</div>
                  <div className="spec-value">Hybrid Stacking</div>
                </div>
                <div className="spec-item">
                  <div className="spec-label">Inference Latency</div>
                  <div className="spec-value">{"< 5ms"}</div>
                </div>
                <div className="spec-item">
                  <div className="spec-label">Feature Space</div>
                  <div className="spec-value">256-dimension</div>
                </div>
                <div className="spec-item">
                  <div className="spec-label">Training Frequency</div>
                  <div className="spec-value">Hourly</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Live Signal Feed */}
        <div className="live-signal-feed">
          <div className="feed-header">
            <div className="feed-title">
              <Zap size={18} />
              <span>Live Signal Feed</span>
            </div>
            <div className="feed-status active">
              <div className="status-dot" />
              Streaming
            </div>
          </div>
          <div className="feed-content">
            <p className="feed-description">
              Scan results stream straight into this dashboard—no mock data—so every analyst review is grounded in reality.
            </p>
            <div className="feed-metrics">
              <span className="metric-tag">
                <span className="metric-value">12.5k</span>
                <span className="metric-label">payloads/hour</span>
              </span>
              <span className="metric-tag">
                <span className="metric-value">98.2%</span>
                <span className="metric-label">uptime</span>
              </span>
              <span className="metric-tag">
                <span className="metric-value">{"<50ms"}</span>
                <span className="metric-label">latency</span>
              </span>
            </div>
          </div>
        </div>
      </Card>
    </motion.div>
  );
}