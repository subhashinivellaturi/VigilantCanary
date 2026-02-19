import React, { useState, useEffect } from 'react';
import { API_URL } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  AlertCircle,
  Info,
  Loader2,
  CheckCircle,
  Shield,
  Eye,
  Filter,
  Download,
  ChevronRight,
  Clock,
  Globe,
  Zap,
  Database,
  // removed BarChart3, RefreshCw, Sparkles (not exported in current lucide-react)
} from 'lucide-react';
import { Card } from './ui/Card';
import './RecentRisks.css';

interface Vulnerability {
  id: string;
  timestamp: string;
  vulnerability_name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affected_url: string;
  scan_type: string;
  cvss_score: number;
  description: string;
  confidence: number;
  status: 'open' | 'investigating' | 'mitigated' | 'resolved';
  affected_host?: string;
  attack_vector?: string;
  recommendations?: string[];
}

interface RecentRisksProps {
  limit?: number;
  showFilters?: boolean;
  autoRefresh?: boolean;
}

const severityConfig: Record<string, any> = {
  critical: { 
    color: '#ef4444', 
    bg: 'rgba(239, 68, 68, 0.15)',
    icon: AlertTriangle, 
    label: 'Critical',
    gradient: 'from-red-500/20 to-orange-500/20'
  },
  high: { 
    color: '#f97316', 
    bg: 'rgba(249, 115, 22, 0.15)',
    icon: AlertTriangle, 
    label: 'High',
    gradient: 'from-orange-500/20 to-amber-500/20'
  },
  medium: { 
    color: '#eab308', 
    bg: 'rgba(234, 179, 8, 0.15)',
    icon: AlertCircle, 
    label: 'Medium',
    gradient: 'from-yellow-500/20 to-amber-500/20'
  },
  low: { 
    color: '#10b981', 
    bg: 'rgba(16, 185, 129, 0.15)',
    icon: Info, 
    label: 'Low',
    gradient: 'from-emerald-500/20 to-green-500/20'
  }
};

const statusConfig = {
  open: { color: '#ef4444', label: 'Open' },
  investigating: { color: '#f59e0b', label: 'Investigating' },
  mitigated: { color: '#3b82f6', label: 'Mitigated' },
  resolved: { color: '#10b981', label: 'Resolved' }
};

const scanTypeIcons: Record<string, any> = {
  'SQL Injection': { icon: <Database size={14} />, color: '#ef4444' },
  'XSS': { icon: <AlertTriangle size={14} />, color: '#f59e0b' },
  'Port Scan': { icon: <Globe size={14} />, color: '#3b82f6' },
  'Subdomain': { icon: <Zap size={14} />, color: '#8b5cf6' },
  'General': { icon: <Database size={14} />, color: '#94a3b8' }
};

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function RecentRisks({ limit = 10, showFilters = true, autoRefresh = false }: RecentRisksProps) {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    open: 0,
    avgCvss: 0
  });

  useEffect(() => {
    fetchRecentVulnerabilities();
    
    if (autoRefresh) {
      const interval = setInterval(fetchRecentVulnerabilities, 30000);
      return () => clearInterval(interval);
    }
  }, [limit, autoRefresh]);

  const fetchRecentVulnerabilities = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch(`${API_URL}/recent-vulnerabilities?limit=${limit}`);
      if (!response.ok) throw new Error('Failed to fetch recent vulnerabilities');
      const data = await response.json();
      
      if (data.status === 'success') {
        const vulns = data.vulnerabilities || [];
        const sorted = vulns.sort(
          (a: Vulnerability, b: Vulnerability) =>
            severityOrder[a.severity] - severityOrder[b.severity]
        );
        
        setVulnerabilities(sorted);
        
        // Calculate stats
        const stats = {
          total: vulns.length,
          critical: vulns.filter((v: Vulnerability) => v.severity === 'critical').length,
          high: vulns.filter((v: Vulnerability) => v.severity === 'high').length,
          medium: vulns.filter((v: Vulnerability) => v.severity === 'medium').length,
          low: vulns.filter((v: Vulnerability) => v.severity === 'low').length,
          open: vulns.filter((v: Vulnerability) => v.status === 'open').length,
          avgCvss: vulns.reduce((acc: number, v: Vulnerability) => acc + v.cvss_score, 0) / vulns.length || 0
        };
        
        setStats(stats);
      } else {
        throw new Error(data.message || 'Failed to fetch vulnerabilities');
      }
    } catch (err) {
      // For demo, create mock data
      createMockData();
    } finally {
      setLoading(false);
    }
  };

  const createMockData = () => {
    const mockVulns: Vulnerability[] = [
      {
        id: '1',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        vulnerability_name: 'SQL Injection',
        severity: 'critical',
        affected_url: 'https://api.example.com/users?id=1',
        scan_type: 'SQL Injection',
        cvss_score: 9.8,
        description: 'SQL injection vulnerability in user authentication endpoint allowing unauthorized access to database.',
        confidence: 0.95,
        status: 'open',
        affected_host: 'api.example.com',
        attack_vector: 'Network',
        recommendations: ['Implement parameterized queries', 'Use ORM with built-in protection', 'Enable WAF rules']
      },
      {
        id: '2',
        timestamp: new Date(Date.now() - 7200000).toISOString(),
        vulnerability_name: 'Cross-Site Scripting (XSS)',
        severity: 'high',
        affected_url: 'https://example.com/contact',
        scan_type: 'XSS',
        cvss_score: 8.2,
        description: 'Reflected XSS vulnerability in contact form allowing script execution in user browsers.',
        confidence: 0.88,
        status: 'investigating',
        affected_host: 'example.com',
        attack_vector: 'Web',
        recommendations: ['Implement CSP headers', 'Sanitize user input', 'Use Content-Security-Policy']
      },
      {
        id: '3',
        timestamp: new Date(Date.now() - 10800000).toISOString(),
        vulnerability_name: 'Open Port Detection',
        severity: 'medium',
        affected_url: '192.168.1.1:22',
        scan_type: 'Port Scan',
        cvss_score: 5.5,
        description: 'SSH port 22 open with weak authentication configuration.',
        confidence: 0.92,
        status: 'mitigated',
        affected_host: '192.168.1.1',
        attack_vector: 'Network',
        recommendations: ['Close unnecessary ports', 'Implement SSH key authentication', 'Enable firewall rules']
      }
    ];
    
    setVulnerabilities(mockVulns);
    setStats({
      total: mockVulns.length,
      critical: mockVulns.filter(v => v.severity === 'critical').length,
      high: mockVulns.filter(v => v.severity === 'high').length,
      medium: mockVulns.filter(v => v.severity === 'medium').length,
      low: 0,
      open: mockVulns.filter(v => v.status === 'open').length,
      avgCvss: mockVulns.reduce((acc, v) => acc + v.cvss_score, 0) / mockVulns.length
    });
  };

  const filteredVulns = vulnerabilities.filter(vuln => {
    if (selectedSeverity !== 'all' && vuln.severity !== selectedSeverity) return false;
    if (selectedStatus !== 'all' && vuln.status !== selectedStatus) return false;
    return true;
  });

  const toggleExpand = (id: string) => {
    setExpandedCard(expandedCard === id ? null : id);
  };

  const openUrl = (url: string) => {
    if (url.startsWith('http')) {
      window.open(url, '_blank');
    }
  };

  const exportReport = () => {
    const report = {
      generated: new Date().toISOString(),
      summary: stats,
      vulnerabilities: filteredVulns
    };
    
    const dataStr = JSON.stringify(report, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `security-risks-report-${Date.now()}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const getScanTypeIcon = (type: string) => {
    return scanTypeIcons[type] || { icon: <Database size={14} />, color: '#94a3b8' };
  };

  return (
    <div className="recent-risks-container">
      {/* Header with Stats */}
      <motion.div 
        className="risks-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <AlertTriangle className="header-icon-svg" />
          </div>
          <div>
            <h1 className="header-title">Recent Security Risks</h1>
            <p className="header-subtitle">Monitor and manage detected vulnerabilities in real-time</p>
          </div>
        </div>
        <div className="header-actions">
          <button className="refresh-btn" onClick={fetchRecentVulnerabilities} disabled={loading}>
            <Loader2 size={16} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="export-btn" onClick={exportReport}>
            <Download size={16} />
            <span>Export</span>
          </button>
        </div>
      </motion.div>

      {/* Stats Overview */}
      <div className="stats-overview">
        <div className="stat-card total">
          <div className="stat-icon">
            <Shield size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total Risks</div>
          </div>
        </div>
        <div className="stat-card critical">
          <div className="stat-icon">
            <AlertTriangle size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.critical}</div>
            <div className="stat-label">Critical</div>
          </div>
        </div>
        <div className="stat-card high">
          <div className="stat-icon">
            <AlertTriangle size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.high}</div>
            <div className="stat-label">High</div>
          </div>
        </div>
        <div className="stat-card open">
          <div className="stat-icon">
            <Eye size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.open}</div>
            <div className="stat-label">Open</div>
          </div>
        </div>
        <div className="stat-card avg-cvss">
          <div className="stat-icon">
            <Database size={20} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.avgCvss.toFixed(1)}</div>
            <div className="stat-label">Avg CVSS</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="filters-section">
          <div className="filters-header">
            <Filter size={18} />
            <span>Filter Risks</span>
          </div>
          <div className="filters-grid">
            <div className="filter-group">
              <span className="filter-label">Severity</span>
              <div className="filter-chips">
                <button 
                  className={`filter-chip ${selectedSeverity === 'all' ? 'active' : ''}`}
                  onClick={() => setSelectedSeverity('all')}
                >
                  All
                </button>
                {Object.entries(severityConfig).map(([key, config]) => (
                  <button
                    key={key}
                    className={`filter-chip ${selectedSeverity === key ? 'active' : ''}`}
                    onClick={() => setSelectedSeverity(key)}
                    style={{ 
                      backgroundColor: selectedSeverity === key ? config.bg : 'transparent',
                      borderColor: config.color
                    }}
                  >
                    <div className="chip-dot" style={{ background: config.color }} />
                    {config.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="filter-group">
              <span className="filter-label">Status</span>
              <div className="filter-chips">
                <button 
                  className={`filter-chip ${selectedStatus === 'all' ? 'active' : ''}`}
                  onClick={() => setSelectedStatus('all')}
                >
                  All
                </button>
                {Object.entries(statusConfig).map(([key, config]) => (
                  <button
                    key={key}
                    className={`filter-chip ${selectedStatus === key ? 'active' : ''}`}
                    onClick={() => setSelectedStatus(key)}
                    style={{ 
                      backgroundColor: selectedStatus === key ? config.color + '20' : 'transparent',
                      borderColor: config.color
                    }}
                  >
                    <div className="chip-dot" style={{ background: config.color }} />
                    {config.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Risks List */}
      <Card className="risks-card">
        <div className="card-header">
          <div className="card-title">
            <span>Detected Vulnerabilities</span>
            <span className="results-count">
              {filteredVulns.length} of {vulnerabilities.length} results
            </span>
          </div>
        </div>

        {loading ? (
          <div className="loading-state">
            <div className="loading-spinner" />
            <span>Loading security risks...</span>
          </div>
        ) : error ? (
          <div className="error-state">
            <AlertCircle size={32} />
            <div>
              <h4>Error Loading Risks</h4>
              <p>{error}</p>
              <button className="retry-btn" onClick={fetchRecentVulnerabilities}>
                Retry
              </button>
            </div>
          </div>
        ) : filteredVulns.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">
              <CheckCircle size={48} />
            </div>
            <h3>No Risks Found</h3>
            <p>Your systems are currently secure. No vulnerabilities match the selected filters.</p>
            <button className="reset-filters" onClick={() => {
              setSelectedSeverity('all');
              setSelectedStatus('all');
            }}>
              Reset Filters
            </button>
          </div>
        ) : (
          <div className="risks-list grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
            <AnimatePresence>
              {filteredVulns.map((vuln, index) => {
                const config = severityConfig[vuln.severity];
                const status = statusConfig[vuln.status];
                const scanIcon = getScanTypeIcon(vuln.scan_type);
                return (
                  <motion.div
                    key={vuln.id}
                    className={`risk-card card--glass border shadow-md flex flex-col gap-2 ${expandedCard === vuln.id ? 'expanded' : ''}`}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ delay: index * 0.05 }}
                    layout
                    onClick={() => toggleExpand(vuln.id)}
                    style={{ borderLeftColor: config.color }}
                  >
                    <div className="risk-header flex-between items-center">
                      <div className="severity-badge" style={{ background: config.bg, color: config.color }}>
                        <config.icon size={16} />
                        <span>{config.label}</span>
                      </div>
                      <span className="scan-type" style={{ color: scanIcon.color }}>
                        {scanIcon.icon}
                        {vuln.scan_type}
                      </span>
                      <span className="timestamp">
                        <Clock size={12} />
                        {new Date(vuln.timestamp).toLocaleTimeString([], { 
                          hour: '2-digit', 
                          minute: '2-digit',
                          day: 'numeric',
                          month: 'short'
                        })}
                      </span>
                    </div>
                    <div className="risk-content">
                      <h3 className="risk-title font-semibold text-lg mb-1">{vuln.vulnerability_name}</h3>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="port-badge bg-slate-700 text-slate-200 px-2 py-1 rounded text-xs">
                          {vuln.affected_url?.split(':')[1] ? `Port ${vuln.affected_url.split(':')[1]}` : 'N/A'}
                        </span>
                        <span className="status-badge px-2 py-1 rounded text-xs" style={{ backgroundColor: `${status.color}20`, color: status.color }}>{status.label}</span>
                      </div>
                      <p className="risk-description text-sm text-slate-300 mb-2">{vuln.description}</p>
                      <div className="flex flex-wrap gap-2 mb-2">
                        <span className="cvss-score-badge bg-slate-800 text-emerald-400 px-2 py-1 rounded text-xs">CVSS: {vuln.cvss_score.toFixed(1)}</span>
                        <span className="confidence-badge bg-slate-800 text-blue-400 px-2 py-1 rounded text-xs">Confidence: {Math.round(vuln.confidence * 100)}%</span>
                      </div>
                      <div className="affected-url text-xs text-slate-400 mb-2">
                        <Globe size={12} className="inline mr-1" />
                        {vuln.affected_url}
                      </div>
                      {expandedCard === vuln.id && (
                        <div className="risk-details mt-2">
                          <div className="details-section mb-2">
                            <h4 className="font-semibold mb-1">Attack Details</h4>
                            <div className="details-grid grid grid-cols-2 gap-2">
                              <div className="detail-item"><span className="detail-label">Host:</span> {vuln.affected_host || 'Unknown'}</div>
                              <div className="detail-item"><span className="detail-label">Vector:</span> {vuln.attack_vector || 'Network'}</div>
                              <div className="detail-item"><span className="detail-label">Confidence:</span> {vuln.confidence > 0.9 ? 'High' : vuln.confidence > 0.7 ? 'Medium' : 'Low'}</div>
                            </div>
                          </div>
                          {vuln.recommendations && vuln.recommendations.length > 0 && (
                            <div className="details-section mb-2">
                              <h4 className="font-semibold mb-1">Recommendations</h4>
                              <ul className="list-disc pl-5">
                                {vuln.recommendations.map((rec, idx) => (
                                  <li key={idx} className="text-xs text-slate-300">{rec}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </Card>

      {/* Quick Actions */}
      <div className="quick-actions">
        <h3 className="actions-title">
          <Zap size={20} />
          <span>Quick Actions</span>
        </h3>
        <div className="actions-grid">
          <button className="action-card" onClick={fetchRecentVulnerabilities}>
            <Loader2 size={20} />
            <span>Refresh Data</span>
            <span className="action-hint">Real-time updates</span>
          </button>
          <button className="action-card" onClick={exportReport}>
            <Download size={20} />
            <span>Export Report</span>
            <span className="action-hint">JSON format</span>
          </button>
          <button className="action-card">
            <Eye size={20} />
            <span>View All</span>
            <span className="action-hint">Full risk database</span>
          </button>
          <button className="action-card">
            <AlertTriangle size={20} />
            <span>Create Alert</span>
            <span className="action-hint">New monitoring rule</span>
          </button>
        </div>
      </div>
    </div>
  );
}