import { useState, useEffect } from "react";
import { 
  Line, 
  LineChart, 
  ResponsiveContainer, 
  Tooltip, 
  XAxis, 
  YAxis,
  CartesianGrid,
  Area,
  AreaChart,
  ReferenceLine,
  Label
} from "recharts";
import { motion } from "framer-motion";
import { 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  Activity, 
  Zap, 
  Shield,
  BarChart3,
  Clock,
  Eye,
  Filter,
  ChevronDown,
  ChevronUp
} from "lucide-react";
import type { ScanResponse } from "../types";
import './RiskTimeline.css';

interface Props {
  result: ScanResponse | null;
  showControls?: boolean;
  timeRange?: '24h' | '7d' | '30d' | '90d';
  onTimeRangeChange?: (range: '24h' | '7d' | '30d' | '90d') => void;
}

interface RiskDataPoint {
  timestamp: string;
  value: number;
  anomalies?: number;
  threats?: number;
  confidence: number;
  status: 'normal' | 'warning' | 'critical';
}

export function RiskTimeline({ 
  result, 
  showControls = true,
  timeRange: externalTimeRange = '7d',
  onTimeRangeChange 
}: Props) {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d' | '90d'>(externalTimeRange);
  const [selectedMetric, setSelectedMetric] = useState<'risk' | 'anomalies' | 'threats'>('risk');
  const [showThreshold, setShowThreshold] = useState(true);
  const [hoveredPoint, setHoveredPoint] = useState<RiskDataPoint | null>(null);
  const [data, setData] = useState<RiskDataPoint[]>([]);
  const [stats, setStats] = useState({
    avgRisk: 0,
    peakRisk: 0,
    trend: 0,
    anomaliesCount: 0,
    threatCount: 0
  });

  useEffect(() => {
    if (onTimeRangeChange) {
      onTimeRangeChange(timeRange);
    }
  }, [timeRange, onTimeRangeChange]);

  useEffect(() => {
    generateTimelineData();
  }, [timeRange, result]);

  const generateTimelineData = () => {
    const points = timeRange === '24h' ? 24 : 
                   timeRange === '7d' ? 7 : 
                   timeRange === '30d' ? 30 : 90;
    
    const now = new Date();
    const generatedData: RiskDataPoint[] = [];
    
    let peakRisk = 0;
    let totalRisk = 0;
    let anomaliesCount = 0;
    let threatCount = 0;

    for (let i = points - 1; i >= 0; i--) {
      const date = new Date(now);
      
      if (timeRange === '24h') {
        date.setHours(date.getHours() - i);
      } else if (timeRange === '7d') {
        date.setDate(date.getDate() - i);
      } else if (timeRange === '30d') {
        date.setDate(date.getDate() - i);
      } else {
        date.setDate(date.getDate() - i * 3);
      }

      // Base risk with some variation
      let baseRisk = 0.2 + Math.random() * 0.3;
      
      // Add spike for recent result
      if (result && i === 0) {
        baseRisk = result.probability || 0.65;
      }
      
      // Add some anomalies
      const anomalies = Math.random() > 0.85 ? Math.floor(Math.random() * 5) + 1 : 0;
      const threats = Math.random() > 0.9 ? Math.floor(Math.random() * 3) + 1 : 0;
      
      const riskValue = Math.min(0.95, baseRisk + (anomalies * 0.05) + (threats * 0.08));
      
      let status: 'normal' | 'warning' | 'critical' = 'normal';
      if (riskValue > 0.7) status = 'critical';
      else if (riskValue > 0.5) status = 'warning';

      const point: RiskDataPoint = {
        timestamp: date.toISOString(),
        value: riskValue,
        anomalies,
        threats,
        confidence: 0.8 + Math.random() * 0.2,
        status
      };

      generatedData.push(point);
      
      totalRisk += riskValue;
      if (riskValue > peakRisk) peakRisk = riskValue;
      anomaliesCount += anomalies;
      threatCount += threats;
    }

    setData(generatedData);
    
    const avgRisk = totalRisk / points;
    const trend = generatedData.length > 1 
      ? ((generatedData[generatedData.length - 1].value - generatedData[0].value) / generatedData[0].value) * 100
      : 0;

    setStats({
      avgRisk,
      peakRisk,
      trend,
      anomaliesCount,
      threatCount
    });
  };

  const formatDate = (timestamp: string) => {
    const date = new Date(timestamp);
    
    if (timeRange === '24h') {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (timeRange === '7d') {
      return date.toLocaleDateString([], { weekday: 'short' });
    } else {
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }
  };

  const formatTooltipDate = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString([], { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getRiskColor = (value: number) => {
    if (value >= 0.7) return '#ef4444';
    if (value >= 0.5) return '#f59e0b';
    if (value >= 0.3) return '#3b82f6';
    return '#10b981';
  };

  const getStatusIcon = (status: RiskDataPoint['status']) => {
    switch (status) {
      case 'critical': return <AlertTriangle size={16} />;
      case 'warning': return <TrendingUp size={16} />;
      default: return <Shield size={16} />;
    }
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const dataPoint = data.find(d => formatDate(d.timestamp) === label);
      return (
        <div className="custom-tooltip">
          <div className="tooltip-header">
            <Clock size={14} />
            <span>{dataPoint ? formatTooltipDate(dataPoint.timestamp) : label}</span>
          </div>
          <div className="tooltip-content">
            <div className="tooltip-metric">
              <div className="metric-dot" style={{ background: getRiskColor(payload[0].value) }} />
              <span className="metric-label">Risk Score:</span>
              <span className="metric-value">{(payload[0].value * 100).toFixed(1)}%</span>
            </div>
            {dataPoint && dataPoint.anomalies && dataPoint.anomalies > 0 && (
              <div className="tooltip-metric">
                <div className="metric-dot" style={{ background: '#f59e0b' }} />
                <span className="metric-label">Anomalies:</span>
                <span className="metric-value">{dataPoint.anomalies}</span>
              </div>
            )}
            {dataPoint && dataPoint.threats && dataPoint.threats > 0 && (
              <div className="tooltip-metric">
                <div className="metric-dot" style={{ background: '#ef4444' }} />
                <span className="metric-label">Threats:</span>
                <span className="metric-value">{dataPoint.threats}</span>
              </div>
            )}
          </div>
        </div>
      );
    }
    return null;
  };

  const getYAxisDomain = () => {
    const maxValue = Math.max(...data.map(d => d.value));
    return [0, Math.ceil(maxValue * 10) / 10];
  };

  return (
    <motion.div 
      className="risk-timeline-container"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <div className="timeline-header">
        <div className="header-content">
          <div className="header-icon">
            <Activity className="header-icon-svg" />
          </div>
          <div>
            <h2 className="header-title">Risk Timeline & Attack Surface Pulse</h2>
            <p className="header-subtitle">Monitor security risk trends and anomaly detection over time</p>
          </div>
        </div>
        <div className="header-stats">
          <div className={`trend-indicator ${stats.trend >= 0 ? 'up' : 'down'}`}>
            {stats.trend >= 0 ? <TrendingUp size={16} /> : <TrendingDown size={16} />}
            <span>{Math.abs(stats.trend).toFixed(1)}%</span>
          </div>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="risk-stats">
        <div className="stat-card">
          <div className="stat-icon">
            <BarChart3 size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{(stats.avgRisk * 100).toFixed(1)}%</div>
            <div className="stat-label">Avg. Risk</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <AlertTriangle size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.peakRisk >= 0.7 ? 'HIGH' : 'MEDIUM'}</div>
            <div className="stat-label">Peak Status</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Zap size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.anomaliesCount}</div>
            <div className="stat-label">Anomalies</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Shield size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.threatCount}</div>
            <div className="stat-label">Threats</div>
          </div>
        </div>
      </div>

      {/* Controls */}
      {showControls && (
        <div className="timeline-controls">
          <div className="time-range-selector">
            {(['24h', '7d', '30d', '90d'] as const).map(range => (
              <button
                key={range}
                className={`time-range-btn ${timeRange === range ? 'active' : ''}`}
                onClick={() => setTimeRange(range)}
              >
                {range}
              </button>
            ))}
          </div>
          
          <div className="metric-selector">
            <div className="selector-label">View:</div>
            <div className="metric-buttons">
              <button
                className={`metric-btn ${selectedMetric === 'risk' ? 'active' : ''}`}
                onClick={() => setSelectedMetric('risk')}
              >
                <TrendingUp size={14} />
                <span>Risk Score</span>
              </button>
              <button
                className={`metric-btn ${selectedMetric === 'anomalies' ? 'active' : ''}`}
                onClick={() => setSelectedMetric('anomalies')}
              >
                <Activity size={14} />
                <span>Anomalies</span>
              </button>
              <button
                className={`metric-btn ${selectedMetric === 'threats' ? 'active' : ''}`}
                onClick={() => setSelectedMetric('threats')}
              >
                <AlertTriangle size={14} />
                <span>Threats</span>
              </button>
            </div>
          </div>

          <div className="view-controls">
            <button
              className={`view-control-btn ${showThreshold ? 'active' : ''}`}
              onClick={() => setShowThreshold(!showThreshold)}
            >
              <Eye size={16} />
              <span>Threshold</span>
            </button>
            <button className="view-control-btn">
              <Filter size={16} />
              <span>Filter</span>
            </button>
          </div>
        </div>
      )}

      {/* Chart Container */}
      <div className="chart-container">
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data} onMouseMove={(e) => {
            if (e.activePayload) {
              setHoveredPoint(e.activePayload[0].payload);
            }
          }} onMouseLeave={() => setHoveredPoint(null)}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="warningGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--warning)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--warning)" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--danger)" stopOpacity={0.1}/>
              </linearGradient>
            </defs>
            
            <CartesianGrid 
              strokeDasharray="3 3" 
              stroke="var(--border)" 
              vertical={false}
            />
            
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={formatDate}
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'var(--text-secondary)', fontSize: 12 }}
            />
            
            <YAxis 
              domain={getYAxisDomain()}
              tickFormatter={(value) => `${Math.round(value * 100)}%`}
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'var(--text-secondary)', fontSize: 12 }}
            />
            
            {/* Threshold Lines */}
            {showThreshold && (
              <>
                <ReferenceLine 
                  y={0.7} 
                  stroke="#ef4444" 
                  strokeDasharray="3 3"
                  strokeWidth={1}
                >
                  <Label 
                    value="Critical" 
                    position="insideTopRight"
                    fill="#ef4444"
                    fontSize={10}
                  />
                </ReferenceLine>
                <ReferenceLine 
                  y={0.5} 
                  stroke="#f59e0b" 
                  strokeDasharray="3 3"
                  strokeWidth={1}
                >
                  <Label 
                    value="Warning" 
                    position="insideTopRight"
                    fill="#f59e0b"
                    fontSize={10}
                  />
                </ReferenceLine>
              </>
            )}
            
            <Tooltip content={<CustomTooltip />} />
            
            {/* Area for risk visualization */}
            <Area
              type="monotone"
              dataKey="value"
              stroke="var(--primary)"
              strokeWidth={3}
              fill="url(#riskGradient)"
              fillOpacity={0.6}
              dot={(props) => {
                const point = data[props.index];
                return (
                  <circle
                    cx={props.cx}
                    cy={props.cy}
                    r={point.status === 'critical' ? 6 : point.status === 'warning' ? 4 : 3}
                    fill={getRiskColor(point.value)}
                    stroke="#fff"
                    strokeWidth={2}
                    className="data-point"
                  />
                );
              }}
              activeDot={(props) => {
                const point = props.payload;
                return (
                  <circle
                    cx={props.cx}
                    cy={props.cy}
                    r={8}
                    fill={getRiskColor(point.value)}
                    stroke="#fff"
                    strokeWidth={3}
                    style={{ filter: 'drop-shadow(0 0 8px currentColor)' }}
                  />
                );
              }}
            />
            
            {/* Line for selected metric */}
            {selectedMetric !== 'risk' && (
              <Line
                type="monotone"
                dataKey={selectedMetric === 'anomalies' ? 'anomalies' : 'threats'}
                stroke={selectedMetric === 'anomalies' ? '#f59e0b' : '#ef4444'}
                strokeWidth={2}
                strokeDasharray="5 5"
                dot={false}
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
        
        {/* Hover Info Panel */}
        {hoveredPoint && (
          <motion.div 
            className="hover-info"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="hover-header">
              <div className="hover-time">
                <Clock size={12} />
                <span>{formatTooltipDate(hoveredPoint.timestamp)}</span>
              </div>
              <div 
                className="hover-status"
                style={{ 
                  backgroundColor: `${getRiskColor(hoveredPoint.value)}20`,
                  color: getRiskColor(hoveredPoint.value)
                }}
              >
                {getStatusIcon(hoveredPoint.status)}
                <span>{hoveredPoint.status.toUpperCase()}</span>
              </div>
            </div>
            <div className="hover-metrics">
              <div className="hover-metric">
                <span className="metric-label">Risk Score</span>
                <span className="metric-value">{(hoveredPoint.value * 100).toFixed(1)}%</span>
              </div>
              <div className="hover-metric">
                <span className="metric-label">Confidence</span>
                <span className="metric-value">{(hoveredPoint.confidence * 100).toFixed(0)}%</span>
              </div>
              {hoveredPoint.anomalies && hoveredPoint.anomalies > 0 && (
                <div className="hover-metric">
                  <span className="metric-label">Anomalies</span>
                  <span className="metric-value">{hoveredPoint.anomalies}</span>
                </div>
              )}
              {hoveredPoint.threats && hoveredPoint.threats > 0 && (
                <div className="hover-metric">
                  <span className="metric-label">Threats</span>
                  <span className="metric-value">{hoveredPoint.threats}</span>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </div>

      {/* Timeline Legend */}
      <div className="timeline-legend">
        <div className="legend-items">
          <div className="legend-item">
            <div className="legend-dot" style={{ background: '#10b981' }} />
            <span>Low Risk (&lt;30%)</span>
          </div>
          <div className="legend-item">
            <div className="legend-dot" style={{ background: '#3b82f6' }} />
            <span>Medium Risk (30-50%)</span>
          </div>
          <div className="legend-item">
            <div className="legend-dot" style={{ background: '#f59e0b' }} />
            <span>High Risk (50-70%)</span>
          </div>
          <div className="legend-item">
            <div className="legend-dot" style={{ background: '#ef4444' }} />
            <span>Critical Risk (&gt;70%)</span>
          </div>
        </div>
        <div className="legend-note">
          <span className="note-text">
            {stats.trend >= 0 ? '↑ Risk increasing' : '↓ Risk decreasing'} over {timeRange}
          </span>
        </div>
      </div>

      {/* Risk Insights */}
      <div className="risk-insights">
        <h3 className="insights-title">
          <AlertTriangle size={20} />
          <span>Risk Insights</span>
        </h3>
        <div className="insights-grid">
          <div className="insight-card">
            <div className="insight-icon">
              <TrendingUp size={20} />
            </div>
            <div className="insight-content">
              <div className="insight-title">Peak Risk Detected</div>
              <div className="insight-value">{(stats.peakRisk * 100).toFixed(1)}%</div>
              <div className="insight-time">During the last {timeRange}</div>
            </div>
          </div>
          <div className="insight-card">
            <div className="insight-icon">
              <Activity size={20} />
            </div>
            <div className="insight-content">
              <div className="insight-title">Anomaly Frequency</div>
              <div className="insight-value">{stats.anomaliesCount} events</div>
              <div className="insight-time">Avg. {Math.round(stats.anomaliesCount / data.length)} per period</div>
            </div>
          </div>
          <div className="insight-card">
            <div className="insight-icon">
              <Shield size={20} />
            </div>
            <div className="insight-content">
              <div className="insight-title">Threat Mitigation</div>
              <div className="insight-value">{stats.threatCount} detected</div>
              <div className="insight-time">{Math.round((stats.threatCount / data.length) * 100)}% threat rate</div>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}