import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Clock, X, AlertTriangle, CheckCircle, Shield, Activity, Zap, Eye, Download, Filter, ChevronDown, ChevronUp, BarChart3, TrendingUp, Search, FileText, RefreshCw, Sparkles } from "lucide-react";
  import type { ScanResponse } from "../types";
  import './ScanHistory.css';

  const SEVERITY_COLORS = {
    critical: { bg: '#ef4444', text: '#fff', icon: <AlertTriangle size={16} /> },
    high: { bg: '#f97316', text: '#fff', icon: <AlertTriangle size={16} /> },
    medium: { bg: '#f59e0b', text: '#1e293b', icon: <Activity size={16} /> },
    low: { bg: '#10b981', text: '#fff', icon: <CheckCircle size={16} /> },
    safe: { bg: '#3b82f6', text: '#fff', icon: <Shield size={16} /> }
  };

  const STATUS_LABELS = {
    vulnerable: 'Vulnerable',
    safe: 'Secure'
  };

  export function ScanHistory({
    visible,
    onClose,
    onExport,
    onViewDetails,
    onRefresh
  }: {
    visible: boolean;
    onClose: () => void;
    onExport?: (scanIds: string[]) => void;
    onViewDetails?: (scan: ScanResponse) => void;
    onRefresh?: () => void;
  }) {
    const [scans, setScans] = useState<ScanResponse[]>([]);
    const [selectedScans, setSelectedScans] = useState<string[]>([]);
    const [filterStatus, setFilterStatus] = useState<string>('all');
    const [filterSeverity, setFilterSeverity] = useState<string>('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [expandedScan, setExpandedScan] = useState<string | null>(null);
    const [sortBy, setSortBy] = useState<'date' | 'severity' | 'probability'>('date');
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

    // Fetch real scan data from backend API (same as Dashboard)
    useEffect(() => {
      async function fetchScans() {
        try {
          const res = await fetch('/api/v1/recent-scans');
          const data = await res.json();
          setScans(Array.isArray(data.scans) ? data.scans : []);
        } catch {
          setScans([]);
        }
      }
      fetchScans();
    }, []);

    // Auto-refresh scan history when a scan completes
    useEffect(() => {
      if (!onRefresh) return;
      const handler = () => {
        // Re-fetch scans after scan completes
        fetch('/api/v1/recent-scans')
          .then(res => res.json())
          .then(data => setScans(Array.isArray(data.scans) ? data.scans : []));
        onRefresh();
      };
      window.addEventListener('scanCompleted', handler);
      return () => window.removeEventListener('scanCompleted', handler);
    }, [onRefresh]);

    const filteredScans = scans.filter(scan => {
      if (filterStatus !== 'all' && scan.label !== filterStatus) return false;
      if (filterSeverity !== 'all' && scan.severity !== filterSeverity) return false;
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const scanText = `${scan.label ?? ''} ${scan.severity ?? ''} ${scan.timestamp ?? ''}`.toLowerCase();
        return scanText.includes(query);
      }
      return true;
    }).sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'date':
          comparison = new Date(b.timestamp ?? 0).getTime() - new Date(a.timestamp ?? 0).getTime();
          break;
        case 'severity': {
          const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };
          comparison = (severityOrder[a.severity ?? 'safe'] ?? 99) - (severityOrder[b.severity ?? 'safe'] ?? 99);
          break;
        }
        case 'probability':
          comparison = (b.probability ?? 0) - (a.probability ?? 0);
          break;
      }
      return sortOrder === 'asc' ? -comparison : comparison;
    });

    const toggleSelectScan = (scanId: string) => {
      setSelectedScans(prev =>
        prev.includes(scanId)
          ? prev.filter(id => id !== scanId)
          : [...prev, scanId]
      );
    };

    const toggleSelectAll = () => {
      if (selectedScans.length === filteredScans.length) {
        setSelectedScans([]);
      } else {
        setSelectedScans(filteredScans.map(scan => scan.timestamp));
      }
    };

    const toggleExpandScan = (scanId: string) => {
      setExpandedScan(expandedScan === scanId ? null : scanId);
    };

    const handleExport = () => {
      if (selectedScans.length > 0 && onExport) {
        onExport(selectedScans);
        setSelectedScans([]);
      }
    };

    const getRiskScore = (probability: number = 0, severity: string = 'safe') => {
      const severityMultiplier: Record<string, number> = {
        critical: 1.0,
        high: 0.8,
        medium: 0.6,
        low: 0.4,
        safe: 0.2
      };
      return Math.round((probability ?? 0) * 100 * (severityMultiplier[severity] ?? 0.2));
    };

    const formatDate = (dateString?: string) => {
      if (!dateString) return '';
      const date = new Date(dateString);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays < 7) return `${diffDays}d ago`;
      return date.toLocaleDateString();
    };

    const formatDateTime = (dateString?: string) => {
      if (!dateString) return '';
      return new Date(dateString).toLocaleString([], {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    };

    const getScanStats = () => {
      const total = scans.length;
      const vulnerable = scans.filter(s => s.label === 'vulnerable').length;
      const critical = scans.filter(s => s.severity === ('critical' as typeof s.severity)).length;
      const avgProbability = total > 0 ? scans.reduce((acc, s) => acc + (s.probability ?? 0), 0) / total : 0;
      return { total, vulnerable, critical, avgProbability };
    };

    const stats = getScanStats();

    return (
      <AnimatePresence>
        {visible && (
          <motion.div
            className="scan-history-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          >
            <motion.div
              className="scan-history-container"
              initial={{ opacity: 0, y: 50, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 50, scale: 0.95 }}
              transition={{ type: "spring", damping: 25 }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="history-header">
                <div className="header-content">
                  <div className="header-icon">
                    <Clock className="header-icon-svg" />
                  </div>
                  <div>
                    <h2 className="header-title">Scan History & Analytics</h2>
                    <p className="header-subtitle">
                      {scans.length} security scans analyzed • Real-time monitoring dashboard
                    </p>
                  </div>
                </div>
              
                <div className="header-actions">
                  <button className="refresh-btn" onClick={() => {
                    fetch('/api/v1/recent-scans')
                      .then(res => res.json())
                      .then(data => setScans(Array.isArray(data.scans) ? data.scans : []));
                    if (onRefresh) onRefresh();
                  }} title="Refresh">
                    <RefreshCw size={20} />
                  </button>
                  <button className="close-btn" onClick={onClose}>
                    <X size={24} />
                  </button>
                </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}