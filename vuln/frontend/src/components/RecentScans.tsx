import React, { useState, useEffect } from 'react';
import { API_URL } from '../api/client';
import { generateUnifiedPDFReport } from '../utils/pdfGenerator';
import {
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  Download,
  Search,
  Filter,
  Eye,
  Trash2,
  X,
  Shield,
  Globe,
  Database,
  Activity,
  TrendingUp,
  Maximize2,
  Minimize2,
} from 'lucide-react';
import { Card } from './ui/Card';
import { useToast } from './ui/Toast';
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
}

type ViewMode = 'grid' | 'table';

export function RecentScans() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [filteredScans, setFilteredScans] = useState<ScanRecord[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  // Always use grid view for dashboard clarity
  const viewMode: ViewMode = 'grid';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { showToast } = useToast();

  // Scan type config
  const scanTypeConfig = {
    vulnerability: { label: 'Vulnerability', icon: Shield, color: '#ef4444' },
    port: { label: 'Port Scan', icon: Globe, color: '#3b82f6' },
    subdomain: { label: 'Subdomain', icon: Database, color: '#8b5cf6' },
    general: { label: 'General', icon: Activity, color: '#10b981' }
  };

  // Status config
  const statusConfig = {
    completed: { label: 'Completed', color: '#10b981' },
    failed: { label: 'Failed', color: '#ef4444' },
    running: { label: 'Running', color: '#3b82f6' },
    queued: { label: 'Queued', color: '#f59e0b' }
  };

  // Severity color config
  const severityColors = {
    critical: '#d946ef',
    high: '#ef4444',
    medium: '#f97316',
    low: '#eab308',
    safe: '#22c55e'
  };

  useEffect(() => {
    fetchRecentScans();
    const handler = () => fetchRecentScans();
    window.addEventListener('scanCompleted', handler);
    return () => window.removeEventListener('scanCompleted', handler);
  }, []);

  useEffect(() => {
    filterScans();
  }, [scans, searchTerm, filterStatus]);

  const fetchRecentScans = async () => {
    try {
      setLoading(true);
      // Fetch vulnerability scans
      const vulnRes = await fetch(`${API_URL}/recent-scans?limit=50`);
      const vulnData = vulnRes.ok ? await vulnRes.json() : { scans: [] };
      // Fetch port scans
      const portRes = await fetch(`${API_URL}/recent-port-scans?limit=20`);
      const portData = portRes.ok ? await portRes.json() : { scans: [] };
      // Fetch subdomain scans
      const subRes = await fetch(`${API_URL}/recent-subdomain-scans?limit=20`);
      const subData = subRes.ok ? await subRes.json() : { scans: [] };

      // Normalize and merge all scans
      const allScans: ScanRecord[] = [];
      // Vulnerability scans
      (vulnData.scans || []).forEach((s: any, idx: number) => {
        const rawId = s.scan_id || s.id || idx;
        allScans.push({
          id: String(rawId) + '-vuln',
          timestamp: s.scan_timestamp || s.timestamp || s.created_at || new Date().toISOString(),
          target: s.target_url || s.scanned_url || s.target || s.url || 'Unknown',
          scanType: Array.isArray(s.scan_types) ? (s.scan_types[0] || 'vulnerability') : (s.scan_type || 'vulnerability'),
          status: s.status || 'completed',
          findings: s.total_findings ?? s.vulnerabilities_found ?? s.findings?.length ?? 0,
          severity: s.risk_status || s.executive_summary?.overall_risk_status?.toLowerCase() || s.severity || 'low',
          duration: s.duration_seconds || s.scan_time_seconds || 0,
        });
      });
      // Port scans
      (portData.scans || []).forEach((s: any, idx: number) => {
        const rawId = s.scan_id || s.id || idx;
        allScans.push({
          id: String(rawId) + '-port',
          timestamp: s.scan_timestamp || s.timestamp || s.created_at || new Date().toISOString(),
          target: s.target_host || s.target || 'Unknown',
          scanType: 'port',
          status: s.status || 'completed',
          findings: s.open_ports?.length ?? s.open_count ?? 0,
          severity: 'low',
          duration: s.duration_seconds || s.scan_time_seconds || 0,
        });
      });
      // Subdomain scans
      (subData.scans || []).forEach((s: any, idx: number) => {
        const rawId = s.scan_id || s.id || idx;
        allScans.push({
          id: String(rawId) + '-subdomain',
          timestamp: s.scan_timestamp || s.timestamp || s.created_at || new Date().toISOString(),
          target: s.base_domain || s.domain || 'Unknown',
          scanType: 'subdomain',
          status: s.status || 'completed',
          findings: s.discovered_subdomains?.length ?? s.total_found ?? 0,
          severity: 'low',
          duration: s.duration_seconds || s.scan_time_seconds || 0,
        });
      });
      // Sort by timestamp descending
      allScans.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setScans(allScans);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
      showToast('Failed to load scan history', 'error');
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const filterScans = () => {
    let filtered = scans;

    // Filter by status
    if (filterStatus !== 'all') {
      filtered = filtered.filter(scan => scan.status === filterStatus);
    }

    // Filter by search term
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(scan =>
        (scan.target && scan.target.toLowerCase().includes(term)) ||
        (scan.scanType && scan.scanType.toLowerCase().includes(term)) ||
        (typeof scan.id === 'string' && scan.id.toLowerCase().includes(term))
      );
    }

    // Filter out scans older than 45 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 45);
    filtered = filtered.filter(scan => new Date(scan.timestamp) >= cutoffDate);

    setFilteredScans(filtered);
  };

  const getScanIcon = (type: string) => {
    const config = scanTypeConfig[type as keyof typeof scanTypeConfig];
    if (!config) return Activity;
    return config.icon;
  };

  const formatDate = (isoDate: string) => {
    try {
      const date = new Date(isoDate);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Invalid date';
    }
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return '-';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    return `${(seconds / 60).toFixed(1)}m`;
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!window.confirm('Delete this scan record?')) return;
    try {
      // Remove scan type suffix for backend
      const numericId = scanId.replace(/-(vuln|port|subdomain)$/i, '');
      const endpoints = [
        `${API_URL}/scan/${encodeURIComponent(numericId)}`,
        `${API_URL}/port-scan/${encodeURIComponent(numericId)}`,
        `${API_URL}/subdomain-scan/${encodeURIComponent(numericId)}`
      ];
      let deleted = false;
      let notFound = false;
      for (const url of endpoints) {
        const res = await fetch(url, { method: 'DELETE' });
        if (res.ok) deleted = true;
        else if (res.status === 404) notFound = true;
      }
      if (deleted) {
        showToast('Scan deleted', 'success');
        fetchRecentScans();
        window.dispatchEvent(new Event('scanCompleted'));
      } else if (notFound) {
        showToast('Scan not found in database', 'info');
      } else {
        showToast('Failed to delete scan from backend', 'error');
      }
    } catch (err) {
      showToast('Failed to delete scan', 'error');
    }
  };

  const handleExportScan = async (scan: ScanRecord) => {
    // Map ScanRecord to UnifiedSecurityReport.recent_scans type
    const mappedScan = {
      id: Number.isFinite(Number(scan.id)) ? Number(scan.id) : Date.now(),
      scan_timestamp: scan.timestamp,
      scanned_url: scan.target,
      scan_mode: scan.scanType,
      status: scan.status,
      findings: scan.findings,
      severity_breakdown: {
        critical: scan.severity === 'critical' ? 1 : 0,
        high: scan.severity === 'high' ? 1 : 0,
        medium: scan.severity === 'medium' ? 1 : 0,
        low: scan.severity === 'low' ? 1 : 0
      }
    };

    const reportData = {
      scan_timestamp: scan.timestamp,
      total_scans: 1,
      last_scan_date: scan.timestamp,
      severity_breakdown: {
        critical: scan.severity === 'critical' ? 1 : 0,
        high: scan.severity === 'high' ? 1 : 0,
        medium: scan.severity === 'medium' ? 1 : 0,
        low: scan.severity === 'low' ? 1 : 0
      },
      open_ports: [],
      discovered_subdomains: [],
      vulnerabilities: [],
      recent_scans: [mappedScan]
    };
    await generateUnifiedPDFReport(reportData);
    showToast('Scan exported as PDF', 'success');
  };

  if (loading) {
    return (
      <div className="recent-scans">
        <div className="scans-header">
          <h1>Scan History</h1>
          <p>View and manage your security scans</p>
        </div>
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading scans...</p>
        </div>
      </div>
    );
  }


  return (
    <div className="recent-scans">
      {/* Header */}
      <div className="scans-header">
        <div>
          <h1>Scan History</h1>
          <p>View your completed and in-progress security scans</p>
        </div>
        <button
          onClick={fetchRecentScans}
          className="btn btn--secondary"
          title="Refresh scan history"
        >
          <TrendingUp size={18} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="scans-filters">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search by target, scan type, or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="clear-search"
            >
              <X size={16} />
            </button>
          )}
        </div>

        <div className="filter-controls">
          <div className="filter-group">
            <Filter size={16} />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="queued">Queued</option>
            </select>
          </div>
        </div>
      </div>

      {/* Empty State */}
      {filteredScans.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">
            <Shield size={48} />
          </div>
          <h3>No scans yet</h3>
          <p>
            {scans.length === 0
              ? 'Start a new security scan to see results here'
              : 'No scans match your filters. Try adjusting your search.'}
          </p>
        </div>
      ) : (
        <div className="scans-grid grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
          {filteredScans.map((scan) => {
            const StatusIcon = scan.status === 'completed' ? CheckCircle :
              scan.status === 'failed' ? AlertCircle :
              scan.status === 'running' ? Loader2 :
              Clock;

            const typeConfig = scanTypeConfig[scan.scanType as keyof typeof scanTypeConfig];
            const TypeIcon = typeConfig?.icon || Activity;

            const statusColor = scan.status === 'completed' ? '#10b981' :
              scan.status === 'failed' ? '#ef4444' :
              scan.status === 'running' ? '#3b82f6' :
              '#f59e0b';

            // Ensure key is always unique
            return (
              <div key={scan.id + '-' + scan.timestamp} className="scan-card card--glass border shadow-md flex flex-col gap-2">
                <div className="scan-card-header flex-between items-center">
                  <div className="scan-card-icon" style={{ color: typeConfig?.color }}>
                    <TypeIcon size={20} />
                  </div>
                  <div className="scan-card-title">
                    <h3 className="font-semibold text-lg">{scan.target}</h3>
                    <p className="scan-card-subtitle text-xs text-slate-400">{scan.id}</p>
                  </div>
                  <div className="scan-card-status px-2 py-1 rounded text-xs" style={{ backgroundColor: `${statusColor}20`, color: statusColor }}>
                    <StatusIcon size={14} />
                    {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  </div>
                </div>

                <div className="scan-card-content flex flex-wrap gap-2 mb-2">
                  <div className="scan-card-stat">
                    <div className="scan-card-stat-label">Type</div>
                    <div className="scan-card-stat-value" style={{ color: typeConfig?.color }}>
                      {typeConfig?.label || 'General'}
                    </div>
                  </div>
                  <div className="scan-card-stat">
                    <div className="scan-card-stat-label">Findings</div>
                    <div className={`scan-card-stat-value ${scan.findings > 0 ? 'danger' : 'success'}`}>{scan.findings}</div>
                  </div>
                </div>

                <div className="scan-card-footer flex-between items-center">
                  <span className="text-xs text-slate-400">{formatDate(scan.timestamp)}</span>
                  <div className="scan-card-actions flex gap-2">
                    <button
                      className="scan-card-action-btn"
                      onClick={() => handleExportScan(scan)}
                      title="Export scan"
                    >
                      <Download size={16} />
                    </button>
                    <button
                      className="scan-card-action-btn delete"
                      onClick={() => handleDeleteScan(scan.id)}
                      title="Delete scan"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default RecentScans;
