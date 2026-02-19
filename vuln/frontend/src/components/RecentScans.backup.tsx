import React, { useState, useEffect } from 'react';
import { API_URL } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  FileText,
  Download,
  Search,
  Filter,
  Eye,
  Trash2,
  X,
  ChevronDown,
  ChevronUp,
  Shield,
  Zap,
  RefreshCw,
  BarChart3,
  Activity,
  Globe,
  Database,
  AlertTriangle,
  // PlayCircle,  // Not available in lucide-react
  // PauseCircle,  // Not available in lucide-react
  TrendingUp,
  Sparkles,
  // Play,  // Fallback for PlayCircle
  // Pause,  // Fallback for PauseCircle
} from 'lucide-react';
import { Card } from './ui/Card';
import { useToast } from './ui/Toast';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import './RecentScans.css';

interface ScanRecord {
  id: string;
  timestamp: string;
  target: string;
  scanType: 'vulnerability' | 'port' | 'subdomain' | 'general';
  status: 'completed' | 'failed' | 'running' | 'queued';
  findings: number;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  duration?: number;
  progress?: number;
  analystNotes?: string;
}

interface RecentScansProps { 
  limit?: number;
  autoRefresh?: boolean;
}

const SCAN_TYPES = {
  vulnerability: { label: 'Vulnerability Scan', icon: <Shield size={16} />, color: '#ef4444', gradient: 'from-red-500/20 to-orange-500/20' },
  port: { label: 'Port Scan', icon: <Globe size={16} />, color: '#3b82f6', gradient: 'from-blue-500/20 to-cyan-500/20' },
  subdomain: { label: 'Subdomain Scan', icon: <Database size={16} />, color: '#8b5cf6', gradient: 'from-purple-500/20 to-pink-500/20' },
  general: { label: 'General Scan', icon: <Activity size={16} />, color: '#10b981', gradient: 'from-green-500/20 to-emerald-500/20' }
};

const STATUS_CONFIG = {
  completed: { label: 'Completed', color: '#10b981', icon: <CheckCircle size={16} /> },
  failed: { label: 'Failed', color: '#ef4444', icon: <AlertCircle size={16} /> },
  running: { label: 'Running', color: '#3b82f6', icon: <Loader2 size={16} className="animate-spin" /> },
  queued: { label: 'Queued', color: '#f59e0b', icon: <Clock size={16} /> }
};

export function RecentScans({ limit = 50, autoRefresh = false }: RecentScansProps) {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [filteredScans, setFilteredScans] = useState<ScanRecord[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('completed');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefreshActive, setAutoRefreshActive] = useState(autoRefresh);
  const [viewingScan, setViewingScan] = useState<ScanRecord | null>(null);
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('list');
  const { showToast } = useToast();

  useEffect(() => {
    fetchRecentScans();
    
    if (autoRefreshActive) {
      const interval = setInterval(fetchRecentScans, 10000);
      return () => clearInterval(interval);
    }
  }, [autoRefreshActive]);

  useEffect(() => {
    let filtered = scans;

    // Filter out scans older than 45 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 45);
    filtered = filtered.filter(scan => {
      const scanDate = new Date(scan.timestamp);
      return scanDate >= cutoffDate;
    });

    // Only show completed scans
    filtered = filtered.filter(scan => scan.status === 'completed');

    if (searchTerm) {
      filtered = filtered.filter(scan =>
        scan.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.id.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (filterType !== 'all') {
      filtered = filtered.filter(scan => scan.scanType === filterType);
    }

    if (filterStatus !== 'all') {
      filtered = filtered.filter(scan => scan.status === filterStatus);
    }

    setFilteredScans(filtered);
  }, [scans, searchTerm, filterType, filterStatus]);

  const fetchRecentScans = async () => {
    try {
      setLoading(true);
      setError(null);
      // Try real API first
      try {
        const res = await fetch(`${API_URL}/recent-scans?limit=${limit}`);
        if (res.ok) {
          const json = await res.json();
          const apiScans = (json.scans || json || []).map((s: any) => ({
            id: s.id || s.scan_id || s.scanId || `SCN-${Math.random().toString(36).slice(2,8)}`,
            timestamp: s.timestamp || s.scan_timestamp || new Date().toISOString(),
            target: s.target || s.scanned_url || s.base_domain || s.target_host || 'unknown',
            scanType: s.scan_type || (s.open_ports ? 'port' : s.discovered_subdomains ? 'subdomain' : 'vulnerability'),
            status: (s.status || 'completed') as any,
            findings: s.vulnerabilities_found ?? s.findings?.length ?? s.total_found ?? 0,
            severity: s.executive_summary?.overall_risk_status?.toLowerCase() as any,
            duration: s.duration_seconds || s.scan_time_seconds || 0,
          }));

          setScans(apiScans);
          setFilteredScans(apiScans);
          setLoading(false);
          return;
        }
      } catch (apiErr) {
        // Continue to mock fallback on error
        console.warn('RecentScans: API fetch failed, falling back to demo data', apiErr);
      }

      // No mock data - clean slate on app start
      const mockScans: ScanRecord[] = [];
      
      setScans(mockScans);
      setFilteredScans(mockScans);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
      showToast('Failed to load scan history', 'error');
    } finally {
      setLoading(false);
    }
  };

  const toggleSelectScan = (id: string) => {
    setSelectedScans(prev =>
      prev.includes(id)
        ? prev.filter(scanId => scanId !== id)
        : [...prev, id]
    );
  };

  const toggleAutoRefresh = () => {
    setAutoRefreshActive(!autoRefreshActive);
    showToast(
      autoRefreshActive ? 'Auto-refresh disabled' : 'Auto-refresh enabled (10s)',
      'info'
    );
  };

  const exportSelectedScans = () => {
    if (selectedScans.length === 0) {
      showToast('No scans selected for export', 'info');
      return;
    }
    
    const selectedData = scans.filter(scan => selectedScans.includes(scan.id));
    const exportData = {
      exportedAt: new Date().toISOString(),
      totalScans: selectedData.length,
      scans: selectedData
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const link = document.createElement('a');
    link.href = dataUri;
    link.download = `security-scans-export-${Date.now()}.json`;
    link.click();
    
    showToast(`Exported ${selectedData.length} scans`, 'success');
  };

  const deleteSelectedScans = () => {
    if (selectedScans.length === 0) {
      showToast('No scans selected for deletion', 'info');
      return;
    }
    
    if (window.confirm(`Delete ${selectedScans.length} selected scan(s)?`)) {
      setScans(prev => prev.filter(scan => !selectedScans.includes(scan.id)));
      setSelectedScans([]);
      showToast(`Deleted ${selectedScans.length} scan(s)`, 'success');
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#f59e0b';
      case 'low': return '#10b981';
      default: return '#94a3b8';
    }
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return '--';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    return date.toLocaleDateString();
  };

  if (loading && scans.length === 0) {
    return (
      <div className="recent-scans-container">
        <motion.div 
          className="scans-header"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="header-content">
            <div className="header-icon">
              <FileText className="header-icon-svg" />
            </div>
            <div>
              <h1 className="header-title">Scan History</h1>
              <p className="header-subtitle">Monitor and manage all security scan operations — loading...</p>
            </div>
          </div>
        </motion.div>
        <div className="scans-content">
          <Skeleton count={5} height="80px" className="mb-4" />
        </div>
      </div>
    );
  }

  return (
    <div className="recent-scans-container">
      {/* Header Section */}
      <motion.div 
        className="scans-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <FileText className="header-icon-svg" />
          </div>
          <div>
            <h1 className="header-title">Scan History</h1>
            <p className="header-subtitle">Monitor completed security scan operations from the last 45 days — executive summaries & exports</p>
          </div>
        </div>
        <div className="header-stats">
          <div className="stat-badge">
            <Activity size={16} />
            <span>Recent Scans: {filteredScans.length}</span>
          </div>
          <div className="stat-badge">
            <CheckCircle size={16} />
            <span>Completed: {scans.filter(s => s.status === 'completed').length}</span>
          </div>
        </div>
      </motion.div>

      {/* Controls Bar */}
      <div className="controls-bar">
        <div className="search-container">
          <Search className="search-icon" />
          <input
            type="text"
            placeholder="Search scans by target, ID, or notes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="controls-group">
          <div className="filter-dropdown">
            <Filter size={16} />
            <select 
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Scan Types</option>
              <option value="vulnerability">Vulnerability</option>
              <option value="port">Port Scan</option>
              <option value="subdomain">Subdomain</option>
              <option value="general">General</option>
            </select>
          </div>

          <div className="filter-dropdown">
            <Activity size={16} />
            <select 
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="queued">Queued</option>
            </select>
          </div>

          <div className="view-toggle">
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

        <div className="action-buttons">
          <button 
            className={`refresh-btn ${autoRefreshActive ? 'active' : ''}`}
            onClick={toggleAutoRefresh}
            title="Toggle auto-refresh"
          >
            {autoRefreshActive ? <Loader2 size={16} /> : <Loader2 size={16} />}
            <span>Auto-refresh</span>
          </button>
          
          <button className="new-scan-btn">
            <Zap size={16} />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {/* Selection Actions */}
      {selectedScans.length > 0 && (
        <motion.div 
          className="selection-bar"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="selection-info">
            <div className="selection-icon">
              <FileText size={20} />
            </div>
            <span>{selectedScans.length} scan(s) selected</span>
          </div>
          <div className="selection-actions">
            <button className="selection-btn export" onClick={exportSelectedScans}>
              <Download size={16} />
              <span>Export</span>
            </button>
            <button className="selection-btn delete" onClick={deleteSelectedScans}>
              <Trash2 size={16} />
              <span>Delete</span>
            </button>
            <button className="selection-btn clear" onClick={() => setSelectedScans([])}>
              <X size={16} />
              <span>Clear</span>
            </button>
          </div>
        </motion.div>
      )}

      {/* Results Info */}
      <div className="results-info">
        <span className="results-count">
          {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''} found
          {searchTerm && ` for "${searchTerm}"`}
        </span>
        <div className="results-filters">
          <span className="filter-tag">
            Type: {filterType === 'all' ? 'All' : SCAN_TYPES[filterType as keyof typeof SCAN_TYPES]?.label}
          </span>
          <span className="filter-tag">
            Status: {filterStatus === 'all' ? 'All' : STATUS_CONFIG[filterStatus as keyof typeof STATUS_CONFIG]?.label}
          </span>
        </div>
      </div>

      {/* Scans List/Grid */}
      {error ? (
        <div className="error-state">
          <AlertCircle size={48} />
          <div className="error-content">
            <h3>Error Loading Scans</h3>
            <p>{error}</p>
            <button className="retry-btn" onClick={fetchRecentScans}>
              <RefreshCw size={16} />
              Retry
            </button>
          </div>
        </div>
      ) : filteredScans.length === 0 ? (
        <EmptyState
          icon={<Search size={48} />}
          title="No Scans Found"
          description="Try adjusting your search criteria or start a new scan"
          action={{
            label: 'Start New Scan',
            onClick: () => console.log('Start new scan')
          }}
        />
      ) : viewMode === 'list' ? (
        <div className="scans-list">
          <AnimatePresence>
            {filteredScans.map((scan) => (
              <motion.div
                key={scan.id}
                className={`scan-card recent-scan-card-hover ${selectedScans.includes(scan.id) ? 'selected' : ''}`}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                layout
                whileHover={{ y: -2, transition: { duration: 0.2 } }}
              >
                {/* Selection Checkbox */}
                <div className="selection-checkbox">
                  <input
                    type="checkbox"
                    checked={selectedScans.includes(scan.id)}
                    onChange={() => toggleSelectScan(scan.id)}
                    id={`select-${scan.id}`}
                  />
                  <label htmlFor={`select-${scan.id}`} />
                </div>

                {/* Scan Type Icon */}
                <div 
                  className="scan-type-icon"
                  style={{ 
                    background: `linear-gradient(135deg, ${SCAN_TYPES[scan.scanType]?.color}20, ${SCAN_TYPES[scan.scanType]?.color}40)`,
                    borderColor: SCAN_TYPES[scan.scanType]?.color
                  }}
                >
                  {SCAN_TYPES[scan.scanType]?.icon}
                </div>

                {/* Scan Info */}
                <div className="scan-info">
                  <div className="scan-header">
                    <div>
                      <h3 className="scan-target">{scan.target}</h3>
                      <div className="scan-meta">
                        <span className="scan-id">ID: {scan.id}</span>
                        <span className="scan-time">{formatDate(scan.timestamp)}</span>
                        {scan.analystNotes && (
                          <span className="scan-notes">{scan.analystNotes}</span>
                        )}
                      </div>
                    </div>
                    <div className="scan-badges">
                      <span 
                        className="scan-type-badge"
                        style={{ 
                          backgroundColor: `${SCAN_TYPES[scan.scanType]?.color}20`,
                          color: SCAN_TYPES[scan.scanType]?.color
                        }}
                      >
                        {SCAN_TYPES[scan.scanType]?.label}
                      </span>
                      {scan.severity && (
                        <span 
                          className="severity-badge scan-risk-badge"
                          style={{ 
                            backgroundColor: `${getSeverityColor(scan.severity)}20`,
                            color: getSeverityColor(scan.severity)
                          }}
                        >
                          {scan.severity.toUpperCase()}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Scan Status & Progress */}
                  <div className="scan-details">
                    <div className="status-container">
                      <div 
                        className="status-badge"
                        style={{ 
                          backgroundColor: `${STATUS_CONFIG[scan.status].color}20`,
                          color: STATUS_CONFIG[scan.status].color
                        }}
                      >
                        {STATUS_CONFIG[scan.status].icon}
                        <span>{STATUS_CONFIG[scan.status].label}</span>
                      </div>
                      
                      {scan.status === 'running' && scan.progress !== undefined && (
                        <div className="progress-container">
                          <div className="progress-bar">
                            <motion.div 
                              className="progress-fill"
                              initial={{ width: 0 }}
                              animate={{ width: `${scan.progress}%` }}
                              transition={{ duration: 1 }}
                              style={{ background: SCAN_TYPES[scan.scanType]?.color }}
                            />
                          </div>
                          <span className="progress-text">{Math.round(scan.progress)}%</span>
                        </div>
                      )}
                    </div>

                    <div className="scan-metrics">
                      <div className="metric">
                        <span className="metric-label">Findings</span>
                        <span className="metric-value">
                          {scan.findings > 0 ? (
                            <span className="findings-highlight">{scan.findings}</span>
                          ) : (
                            <span className="findings-zero">{scan.findings}</span>
                          )}
                        </span>
                      </div>
                      <div className="metric">
                        <span className="metric-label">Duration</span>
                        <span className="metric-value">{formatDuration(scan.duration)}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="scan-actions">
                  <button 
                    className="action-btn view"
                    onClick={() => setExpandedScan(expandedScan === scan.id ? null : scan.id)}
                  >
                    <Eye size={16} />
                    <span>View Details</span>
                  </button>
                  <button className="action-btn export">
                    <Download size={16} />
                    <span>Export</span>
                  </button>
                  <button 
                    className="action-btn delete"
                    onClick={() => {
                      if (window.confirm(`Delete scan ${scan.id}?`)) {
                        setScans(prev => prev.filter(s => s.id !== scan.id));
                        showToast(`Scan ${scan.id} deleted`, 'success');
                      }
                    }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>

                {/* Expandable Details */}
                <AnimatePresence>
                  {expandedScan === scan.id && (
                    <motion.div
                      className="scan-expanded"
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                    >
                      <div className="expanded-content">
                        <div className="expanded-section">
                          <h4>Scan Information</h4>
                          <div className="info-grid">
                            <div className="info-item">
                              <span className="info-label">Target</span>
                              <span className="info-value">{scan.target}</span>
                            </div>
                            <div className="info-item">
                              <span className="info-label">Scan ID</span>
                              <span className="info-value">{scan.id}</span>
                            </div>
                            <div className="info-item">
                              <span className="info-label">Start Time</span>
                              <span className="info-value">
                                {new Date(scan.timestamp).toLocaleString()}
                              </span>
                            </div>
                            <div className="info-item">
                              <span className="info-label">Duration</span>
                              <span className="info-value">{formatDuration(scan.duration)}</span>
                            </div>
                          </div>
                        </div>

                        {scan.analystNotes && (
                          <div className="expanded-section">
                            <h4>Analyst Notes</h4>
                            <p className="notes-text">{scan.analystNotes}</p>
                          </div>
                        )}

                        <div className="expanded-actions">
                          <button className="expanded-btn primary">
                            <Eye size={16} />
                            <span>View Full Report</span>
                          </button>
                          <button className="expanded-btn secondary">
                            <Download size={16} />
                            <span>Download JSON</span>
                          </button>
                          <button className="expanded-btn outline">
                            <AlertTriangle size={16} />
                            <span>Create Alert</span>
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      ) : (
        <div className="scans-grid">
          {filteredScans.map((scan) => (
            <motion.div
              key={scan.id}
              className="scan-grid-card"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ y: -5, transition: { duration: 0.2 } }}
            >
              <div className="grid-card-header">
                <div 
                  className="grid-type-icon"
                  style={{ 
                    background: `linear-gradient(135deg, ${SCAN_TYPES[scan.scanType]?.color}20, ${SCAN_TYPES[scan.scanType]?.color}40)`,
                    color: SCAN_TYPES[scan.scanType]?.color
                  }}
                >
                  {SCAN_TYPES[scan.scanType]?.icon}
                </div>
                <div className="grid-selection">
                  <input
                    type="checkbox"
                    checked={selectedScans.includes(scan.id)}
                    onChange={() => toggleSelectScan(scan.id)}
                    id={`grid-select-${scan.id}`}
                  />
                  <label htmlFor={`grid-select-${scan.id}`} />
                </div>
              </div>

              <div className="grid-card-content">
                <h3 className="grid-target">{scan.target}</h3>
                <div className="grid-meta">
                  <span className="grid-id">#{scan.id}</span>
                  <span className="grid-time">{formatDate(scan.timestamp)}</span>
                </div>

                <div className="grid-status">
                  <div 
                    className="grid-status-badge"
                    style={{ 
                      backgroundColor: `${STATUS_CONFIG[scan.status].color}20`,
                      color: STATUS_CONFIG[scan.status].color
                    }}
                  >
                    {STATUS_CONFIG[scan.status].icon}
                    {STATUS_CONFIG[scan.status].label}
                  </div>
                </div>

                {scan.severity && (
                  <div className="grid-severity">
                    <div 
                      className="severity-indicator"
                      style={{ backgroundColor: getSeverityColor(scan.severity) }}
                    />
                    <span className="severity-text">{scan.severity.toUpperCase()}</span>
                  </div>
                )}

                <div className="grid-metrics">
                  <div className="grid-metric">
                    <span className="metric-label">Findings</span>
                    <span className="metric-value">{scan.findings}</span>
                  </div>
                  <div className="grid-metric">
                    <span className="metric-label">Duration</span>
                    <span className="metric-value">{formatDuration(scan.duration)}</span>
                  </div>
                </div>

                {scan.status === 'running' && scan.progress !== undefined && (
                  <div className="grid-progress">
                    <div className="progress-bar">
                      <div 
                        className="progress-fill"
                        style={{ 
                          width: `${scan.progress}%`,
                          background: SCAN_TYPES[scan.scanType]?.color
                        }}
                      />
                    </div>
                    <span className="progress-text">{Math.round(scan.progress)}%</span>
                  </div>
                )}
              </div>

              <div className="grid-card-actions">
                <button className="grid-action-btn">
                  <Eye size={16} />
                </button>
                <button className="grid-action-btn">
                  <Download size={16} />
                </button>
                <button className="grid-action-btn">
                  <AlertTriangle size={16} />
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Quick Stats */}
      <div className="quick-stats">
        <div className="stats-card">
          <div className="stats-icon">
            <TrendingUp size={20} />
          </div>
          <div className="stats-content">
            <div className="stats-value">
              {scans.filter(s => s.status === 'completed').length}
            </div>
            <div className="stats-label">Successful Scans</div>
          </div>
        </div>
        <div className="stats-card">
          <div className="stats-icon">
            <Sparkles size={20} />
          </div>
          <div className="stats-content">
            <div className="stats-value">
              {scans.reduce((acc, scan) => acc + scan.findings, 0)}
            </div>
            <div className="stats-label">Total Findings</div>
          </div>
        </div>
        <div className="stats-card">
          <div className="stats-icon">
            <Clock size={20} />
          </div>
          <div className="stats-content">
            <div className="stats-value">
              {Math.round(scans.reduce((acc, scan) => acc + (scan.duration || 0), 0) / 60)}
            </div>
            <div className="stats-label">Total Hours</div>
          </div>
        </div>
      </div>
    </div>
  );
}