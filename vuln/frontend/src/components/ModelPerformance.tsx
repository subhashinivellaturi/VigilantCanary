import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PolarAngleAxis,
  PolarGrid,
  Cell,
  LabelList
} from "recharts";
import type { ModelSnapshot } from "../types";
import { 
  TrendingUp, 
  Activity, 
  Target, 
  Zap, 
  AlertTriangle,
  Clock,
  BarChart3,
  // LineChart,  // Not in lucide-react
  Shield,
  Cpu,
  RefreshCw,
  Database
} from "lucide-react";
import './ModelPerformance.css';

interface Props {
  snapshot: ModelSnapshot;
  datasetSize: number;
  modelVersion?: string;
}

interface Metric {
  label: string;
  value: number;
  color: string;
  icon: JSX.Element;
}

export function ModelPerformance({ snapshot, datasetSize, modelVersion }: Props) {
  const [timeRange, setTimeRange] = useState<"7d" | "30d" | "90d">("30d");
  const [activeMetric, setActiveMetric] = useState<string>("accuracy");
  const [simulatedData, setSimulatedData] = useState<any[]>([]);

  // Generate enhanced historical data
  useEffect(() => {
    const ranges = {
      "7d": 7,
      "30d": 30,
      "90d": 90
    };
    
    const data = Array.from({ length: ranges[timeRange] }, (_, i) => ({
      day: `Day ${i + 1}`,
      accuracy: snapshot.accuracy * 100 - Math.random() * 3 + i * 0.2,
      precision: snapshot.precision * 100 - Math.random() * 2 + i * 0.15,
      recall: snapshot.recall * 100 - Math.random() * 2.5 + i * 0.18,
      latency: 50 + Math.random() * 30 - i * 0.1,
      threats: Math.floor(Math.random() * 50 + 100 - i * 0.5)
    }));
    
    setSimulatedData(data);
  }, [timeRange, snapshot]);

  const metricDialData = [
    { name: "Accuracy", value: Math.round(snapshot.accuracy * 100), fill: "#10b981", icon: <Target /> },
    { name: "Precision", value: Math.round(snapshot.precision * 100), fill: "#3b82f6", icon: <Activity /> },
    { name: "Recall", value: Math.round(snapshot.recall * 100), fill: "#8b5cf6", icon: <Zap /> },
    { name: "F1 Score", value: Math.round(snapshot.f1 * 100), fill: "#f59e0b", icon: <BarChart3 /> },
  ];

  const qualityBars = [
    { label: "Precision", value: snapshot.precision * 100, color: "#3b82f6" },
    { label: "Recall", value: snapshot.recall * 100, color: "#8b5cf6" },
    { label: "F1", value: snapshot.f1 * 100, color: "#f59e0b" },
    { label: "Specificity", value: snapshot.accuracy * 100 - 5, color: "#10b981" },
  ];

  const systemMetrics: Metric[] = [
    { label: "Inference Latency", value: 24, color: "#10b981", icon: <Zap /> },
    { label: "Model Drift", value: Math.max(2, Math.round((1 - snapshot.accuracy) * 40)), color: "#f59e0b", icon: <TrendingUp /> },
    { label: "Noise Ratio", value: Math.max(1, Math.round((1 - snapshot.precision) * 35)), color: "#ef4444", icon: <AlertTriangle /> },
    { label: "CPU Usage", value: 65, color: "#3b82f6", icon: <Cpu /> },
  ];

  const performanceStats = [
    { label: "Avg Accuracy", value: `${Math.round(snapshot.accuracy * 1000) / 10}%`, trend: "+2.3%" },
    { label: "Detection Rate", value: `${Math.round(snapshot.recall * 100)}%`, trend: "+1.8%" },
    { label: "False Positive", value: `${Math.round((1 - snapshot.precision) * 100)}%`, trend: "-0.5%" },
    { label: "Response Time", value: "24ms", trend: "-3ms" },
  ];

  const getAccuracyLevel = (accuracy: number) => {
    if (accuracy >= 0.95) return { label: "Excellent", color: "#10b981", icon: "🚀" };
    if (accuracy >= 0.90) return { label: "Good", color: "#3b82f6", icon: "✅" };
    if (accuracy >= 0.85) return { label: "Fair", color: "#f59e0b", icon: "⚠️" };
    return { label: "Needs Attention", color: "#ef4444", icon: "🔴" };
  };

  const accuracyLevel = getAccuracyLevel(snapshot.accuracy);

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="custom-tooltip">
          <div className="tooltip-header">{label}</div>
          {payload.map((entry: any, index: number) => (
            <div key={index} className="tooltip-item">
              <div className="tooltip-dot" style={{ background: entry.color }} />
              <span className="tooltip-label">{entry.dataKey}:</span>
              <span className="tooltip-value">{entry.value.toFixed(1)}%</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <motion.section 
      className="model-performance"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <div className="performance-header">
        <div className="header-content">
          <div className="title-section">
            <div className="title-icon">
              {/* <LineChart size={28} /> */}
            </div>
            <div>
              <h2 className="title">Model Performance Analytics</h2>
              <p className="subtitle">
                Real-time monitoring of accuracy, precision, recall, and system metrics
              </p>
            </div>
          </div>
          <div className="header-stats">
            <div className="accuracy-badge" style={{ borderColor: accuracyLevel.color }}>
              <span className="accuracy-icon">{accuracyLevel.icon}</span>
              <div>
                <div className="accuracy-value">{Math.round(snapshot.accuracy * 1000) / 10}%</div>
                <div className="accuracy-label">{accuracyLevel.label} Accuracy</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        {performanceStats.map((stat, index) => (
          <div key={index} className="stat-card">
            <div className="stat-header">
              <div className="stat-label">{stat.label}</div>
              <div className={`stat-trend ${stat.trend.startsWith('+') ? 'positive' : 'negative'}`}>
                {stat.trend}
              </div>
            </div>
            <div className="stat-value">{stat.value}</div>
            <div className="stat-progress">
              <div 
                className="progress-bar"
                style={{ 
                  width: `${Math.min(100, (parseFloat(stat.value) || 0) * 1.2)}%`,
                  background: `linear-gradient(90deg, ${index === 0 ? '#10b981' : index === 1 ? '#3b82f6' : index === 2 ? '#ef4444' : '#8b5cf6'}, ${index === 0 ? '#34d399' : index === 1 ? '#60a5fa' : index === 2 ? '#f87171' : '#a78bfa'})`
                }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Main Charts Grid */}
      <div className="charts-grid">
        {/* Accuracy Trend Chart */}
        <div className="chart-card large">
          <div className="chart-header">
            <div className="chart-title">
              <TrendingUp size={20} />
              <span>Accuracy Trend & Model Drift</span>
            </div>
            <div className="time-range-selector">
              {(["7d", "30d", "90d"] as const).map(range => (
                <button
                  key={range}
                  className={`time-btn ${timeRange === range ? 'active' : ''}`}
                  onClick={() => setTimeRange(range)}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={simulatedData}>
                <defs>
                  <linearGradient id="accuracyGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.1} />
                  </linearGradient>
                  <linearGradient id="precisionGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis 
                  dataKey="day" 
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#94a3b8', fontSize: 12 }}
                />
                <YAxis 
                  tickFormatter={(value) => `${value}%`}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#94a3b8', fontSize: 12 }}
                  domain={[85, 100]}
                />
                <Tooltip content={<CustomTooltip />} />
                <Area 
                  type="monotone" 
                  dataKey="accuracy" 
                  stroke="#10b981" 
                  strokeWidth={3}
                  fill="url(#accuracyGradient)" 
                  fillOpacity={0.6}
                  dot={{ stroke: '#10b981', strokeWidth: 2, r: 4 }}
                  activeDot={{ r: 6, stroke: '#10b981', strokeWidth: 2, fill: '#fff' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="precision" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  fill="url(#precisionGradient)" 
                  fillOpacity={0.4}
                  dot={{ stroke: '#3b82f6', strokeWidth: 2, r: 3 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-legend">
            <div className="legend-item">
              <div className="legend-dot" style={{ background: '#10b981' }} />
              <span>Accuracy</span>
            </div>
            <div className="legend-item">
              <div className="legend-dot" style={{ background: '#3b82f6' }} />
              <span>Precision</span>
            </div>
          </div>
        </div>

        {/* Radial Performance Chart */}
        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">
              <Target size={20} />
              <span>Performance Metrics</span>
            </div>
            <div className="model-info">
              <Database size={14} />
              <span>{datasetSize.toLocaleString()} samples</span>
            </div>
          </div>
          <div className="radial-chart-container">
            <ResponsiveContainer width="100%" height={280}>
              <RadialBarChart 
                innerRadius="20%" 
                outerRadius="90%" 
                data={metricDialData}
                startAngle={180}
                endAngle={-180}
              >
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis 
                  type="number" 
                  domain={[0, 100]} 
                  tick={false}
                />
                <RadialBar 
                  dataKey="value"
                  background={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  cornerRadius={8}
                >
                  {metricDialData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                  <LabelList 
                    dataKey="value" 
                    position="insideStart" 
                    fill="#fff" 
                    fontSize={12}
                    fontWeight="bold"
                    formatter={(value: number) => `${value}%`}
                  />
                </RadialBar>
                <Tooltip formatter={(value: number) => [`${value}%`, 'Score']} />
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
          <div className="metric-labels">
            {metricDialData.map((metric, index) => (
              <div key={index} className="metric-label">
                <div className="metric-icon" style={{ color: metric.fill }}>
                  {metric.icon}
                </div>
                <div>
                  <div className="metric-name">{metric.name}</div>
                  <div className="metric-value">{metric.value}%</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quality Bars Chart */}
        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">
              <BarChart3 size={20} />
              <span>Signal Quality</span>
            </div>
            <div className="chart-actions">
              <button className="refresh-btn">
                <RefreshCw size={14} />
                Refresh
              </button>
            </div>
          </div>
          <div className="bars-chart-container">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={qualityBars} barSize={40}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis 
                  dataKey="label" 
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#94a3b8', fontSize: 12 }}
                />
                <YAxis 
                  domain={[0, 100]}
                  tickFormatter={(value) => `${value}%`}
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#94a3b8', fontSize: 12 }}
                />
                <Tooltip formatter={(value: number) => [`${value.toFixed(1)}%`, 'Score']} />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {qualityBars.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                  <LabelList 
                    dataKey="value" 
                    position="top" 
                    fill="#fff" 
                    fontSize={12}
                    fontWeight="bold"
                    formatter={(value: number) => `${value}%`}
                  />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* System Metrics */}
        <div className="chart-card">
          <div className="chart-header">
            <div className="chart-title">
              <Activity size={20} />
              <span>System Health</span>
            </div>
            <div className="health-status">
              <div className="status-dot healthy" />
              <span>Healthy</span>
            </div>
          </div>
          <div className="system-metrics">
            {systemMetrics.map((metric, index) => (
              <div key={index} className="system-metric">
                <div className="metric-header">
                  <div className="metric-icon" style={{ color: metric.color }}>
                    {metric.icon}
                  </div>
                  <div className="metric-name">{metric.label}</div>
                </div>
                <div className="metric-value-container">
                  <div className="metric-value">{metric.value}{metric.label.includes('Usage') ? '%' : ''}</div>
                  <div className="metric-progress">
                    <div 
                      className="progress-track"
                      style={{ background: `${metric.color}20` }}
                    >
                      <motion.div 
                        className="progress-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${metric.value}%` }}
                        transition={{ duration: 1, delay: index * 0.1 }}
                        style={{ background: metric.color }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Model Info Card */}
        <div className="info-card">
          <div className="info-header">
            <Shield size={24} />
            <div>
              <h3>Model Information</h3>
              <p className="info-subtitle">Production Ensemble v2.1.4</p>
            </div>
          </div>
          <div className="info-content">
            <div className="info-item">
              <span className="info-label">Last Trained</span>
              <span className="info-value">
                <Clock size={14} />
                {modelVersion ? new Date(modelVersion).toLocaleDateString() : "2 hours ago"}
              </span>
            </div>
            <div className="info-item">
              <span className="info-label">Training Samples</span>
              <span className="info-value">{datasetSize.toLocaleString()}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Model Type</span>
              <span className="info-value">Hybrid Ensemble</span>
            </div>
            <div className="info-item">
              <span className="info-label">Inference Speed</span>
              <span className="info-value">24ms avg</span>
            </div>
          </div>
          <div className="info-footer">
            <div className="uptime-indicator">
              <div className="uptime-dot" />
              <span>99.8% Uptime</span>
            </div>
            <button className="retrain-btn">
              <RefreshCw size={14} />
              Retrain Model
            </button>
          </div>
        </div>
      </div>
    </motion.section>
  );
}