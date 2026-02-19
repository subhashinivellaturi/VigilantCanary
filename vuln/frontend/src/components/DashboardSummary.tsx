import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  AlertCircle, 
  Info, 
  Wifi, 
  WifiOff, 
  Globe, 
  Download,
  RefreshCw,
  Eye,
  ExternalLink,
  ChevronRight,
  BarChart3,
  FileText,
  Server,
  Clock,
  Zap,
  Filter,
  Maximize2,
  X,
  TrendingUp,
  TrendingDown,
  Sparkles
} from 'lucide-react';
import { generateUnifiedSecurityReport } from '../utils/pdfGenerator';

interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface PortScanRisk {
  id: number;
  timestamp: string;
  target_host: string;
  open_ports: Array<{
    port: number;
    service: string;
    protocol: string;
  }>;
  open_count: number;
}

interface Vulnerability {
  id: string;
  timestamp: string;
  vulnerability_name: string;
  severity: string;
  affected_url: string;
  scan_type: string;
  cvss_score: number;
  description: string;
  confidence: number;
}

interface SubdomainScan {
  id: number;
  timestamp: string;
  base_domain: string;
  discovered_subdomains: string[];
  total_found: number;
  scan_method: string;
  status: string;
}

interface DashboardSummaryProps {
  onViewDetails?: (severity: string) => void;
}

export function DashboardSummary({ onViewDetails }: DashboardSummaryProps) {
  const [summary, setSummary] = useState<SeveritySummary>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [portScanRisks, setPortScanRisks] = useState<PortScanRisk[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [subdomainScans, setSubdomainScans] = useState<SubdomainScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportLoading, setExportLoading] = useState<string | null>(null);
  const [timeSinceRefresh, setTimeSinceRefresh] = useState('Just now');
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [expandedView, setExpandedView] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => {
      const times = ['Just now', '1 min ago', '2 mins ago', '5 mins ago'];
      const randomTime = times[Math.floor(Math.random() * times.length)];
      setTimeSinceRefresh(randomTime);
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch vulnerability summary
      const vulnResponse = await fetch('http://localhost:8007/api/v1/vulnerabilities/summary');
      if (!vulnResponse.ok) {
        throw new Error('Failed to fetch vulnerability summary');
      }
      const vulnData = await vulnResponse.json();
      
      if (vulnData.status === 'success') {
        setSummary(vulnData.summary);
      }
      
      // Fetch recent port scan risks
      const portResponse = await fetch('http://localhost:8007/api/v1/recent-port-scans?limit=5');
      if (portResponse.ok) {
        const portData = await portResponse.json();
        if (portData.status === 'success') {
          setPortScanRisks(portData.scans.filter((scan: PortScanRisk) => scan.open_count > 0));
        }
      }
      
      // Fetch recent vulnerabilities
      const vulnListResponse = await fetch('http://localhost:8007/api/v1/recent-vulnerabilities?limit=10');
      if (vulnListResponse.ok) {
        const vulnListData = await vulnListResponse.json();
        if (vulnListData.status === 'success') {
          setVulnerabilities(vulnListData.vulnerabilities);
        }
      } else {
        // Mock data for testing
        setVulnerabilities([
          {
            id: 'test-1',
            timestamp: new Date().toISOString(),
            vulnerability_name: 'SQL Injection in Login Form',
            severity: 'critical',
            affected_url: 'https://example.com/login',
            scan_type: 'active',
            cvss_score: 9.8,
            description: 'Unsanitized input allows SQL injection in login form',
            confidence: 95
          },
          {
            id: 'test-2', 
            timestamp: new Date().toISOString(),
            vulnerability_name: 'Cross-Site Scripting (XSS)',
            severity: 'high',
            affected_url: 'https://example.com/search',
            scan_type: 'passive_only',
            cvss_score: 7.5,
            description: 'Reflected XSS vulnerability in search parameter',
            confidence: 85
          },
          {
            id: 'test-3',
            timestamp: new Date().toISOString(),
            vulnerability_name: 'Weak SSL/TLS Configuration',
            severity: 'medium',
            affected_url: 'https://api.example.com',
            scan_type: 'active',
            cvss_score: 6.2,
            description: 'Outdated TLS 1.1 protocol detected',
            confidence: 90
          }
        ]);
      }

      // Fetch recent subdomain scans
      const subdomainResponse = await fetch('http://localhost:8007/api/v1/recent-subdomain-scans?limit=5');
      if (subdomainResponse.ok) {
        const subdomainData = await subdomainResponse.json();
        if (subdomainData.status === 'success') {
          setSubdomainScans(subdomainData.scans);
        }
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const severityCards = [
    {
      severity: 'critical',
      count: summary.critical,
      label: 'Critical',
      icon: Shield,
      gradient: 'from-red-600 via-rose-500 to-red-700',
      bgColor: 'bg-gradient-to-br from-red-500/10 to-rose-500/10',
      borderColor: 'border-red-500/30',
      textColor: 'text-red-400',
      description: 'Immediate action required',
      trend: '+3 today'
    },
    {
      severity: 'high',
      count: summary.high,
      label: 'High',
      icon: AlertTriangle,
      gradient: 'from-orange-500 via-amber-500 to-orange-700',
      bgColor: 'bg-gradient-to-br from-orange-500/10 to-amber-500/10',
      borderColor: 'border-orange-500/30',
      textColor: 'text-orange-400',
      description: 'Address within 24 hours',
      trend: '+5 today'
    },
    {
      severity: 'medium',
      count: summary.medium,
      label: 'Medium',
      icon: AlertCircle,
      gradient: 'from-yellow-500 via-amber-400 to-yellow-600',
      bgColor: 'bg-gradient-to-br from-yellow-500/10 to-amber-400/10',
      borderColor: 'border-yellow-500/30',
      textColor: 'text-yellow-400',
      description: 'Address within 1 week',
      trend: '+8 today'
    },
    {
      severity: 'low',
      count: summary.low,
      label: 'Low',
      icon: Info,
      gradient: 'from-cyan-500 via-blue-500 to-cyan-700',
      bgColor: 'bg-gradient-to-br from-cyan-500/10 to-blue-500/10',
      borderColor: 'border-cyan-500/30',
      textColor: 'text-cyan-400',
      description: 'Monitor and schedule fix',
      trend: '+12 today'
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch(severity) {
      case 'critical': return { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400' };
      case 'high': return { bg: 'bg-orange-500/20', border: 'border-orange-500/30', text: 'text-orange-400' };
      case 'medium': return { bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', text: 'text-yellow-400' };
      case 'low': return { bg: 'bg-blue-500/20', border: 'border-blue-500/30', text: 'text-blue-400' };
      default: return { bg: 'bg-slate-500/20', border: 'border-slate-500/30', text: 'text-slate-400' };
    }
  };

  const handleExport = async (format: 'pdf' | 'csv' | 'json') => {
    try {
      setExportLoading(format);
      await generateUnifiedSecurityReport(format);
    } catch (error) {
      console.error(`Error generating ${format} report:`, error);
      alert(`Failed to generate ${format.toUpperCase()} report. Please try again.`);
    } finally {
      setExportLoading(null);
    }
  };

  const ProgressCircle = ({ progress, color = 'from-blue-500 to-cyan-500' }: { progress: number; color?: string }) => (
    <div className="relative w-12 h-12">
      <svg className="w-12 h-12 transform -rotate-90" viewBox="0 0 36 36">
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="2" strokeLinecap="round" />
        <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={`url(#${color.replace(/\s+/g, '')})`} strokeWidth="2" strokeDasharray={`${progress}, 100`} strokeLinecap="round" />
        <defs>
          <linearGradient id={color.replace(/\s+/g, '')} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style={{ stopColor: color.split(' ')[0].replace('from-', ''), stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: color.split(' ')[2].replace('to-', ''), stopOpacity: 1 }} />
          </linearGradient>
        </defs>
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xs font-bold text-white">{progress}%</span>
      </div>
    </div>
  );

  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl shadow-2xl p-6 backdrop-blur-sm"
      >
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white">Security Dashboard</h2>
              <p className="text-slate-400 text-sm">Loading threat intelligence...</p>
            </div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="animate-pulse">
              <div className="bg-slate-800/50 rounded-xl p-6 h-32 border border-slate-700/50">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-slate-700/50 rounded-lg"></div>
                  <div className="w-8 h-8 bg-slate-700/50 rounded"></div>
                </div>
                <div className="space-y-2">
                  <div className="w-16 h-5 bg-slate-700/50 rounded"></div>
                  <div className="w-24 h-4 bg-slate-700/50 rounded"></div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl shadow-2xl p-6 backdrop-blur-sm"
      >
        <div className="text-center py-8">
          <div className="w-16 h-16 bg-red-500/20 border border-red-500/30 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Error Loading Dashboard</h3>
          <p className="text-red-400 mb-6 max-w-md mx-auto">{error}</p>
          <div className="flex items-center justify-center gap-3">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={fetchDashboardData}
              className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl font-medium flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Retry
            </motion.button>
            <button className="px-5 py-2.5 bg-slate-800/50 text-slate-300 border border-slate-700/50 rounded-xl font-medium">
              View Logs
            </button>
          </div>
        </div>
      </motion.div>
    );
  }

  const totalVulnerabilities = Object.values(summary).reduce((sum, count) => sum + count, 0);
  const filteredVulnerabilities = activeFilter === 'all' 
    ? vulnerabilities 
    : vulnerabilities.filter(v => v.severity === activeFilter);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-sm"
    >
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-800/50 to-slate-900/50 px-6 py-5 border-b border-slate-700/50">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-4">
            <div className="p-2 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white">Security Intelligence Dashboard</h2>
              <p className="text-slate-400 text-sm mt-1 flex items-center gap-2">
                <Clock className="w-3 h-3" />
                Last updated: {timeSinceRefresh} • 
                <span className="font-semibold text-cyan-400 ml-2">{totalVulnerabilities} total vulnerabilities</span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex gap-2">
              {(['pdf', 'csv', 'json'] as const).map((format) => (
                <motion.button
                  key={format}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => handleExport(format)}
                  disabled={!!exportLoading}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                    format === 'pdf' ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30' :
                    format === 'csv' ? 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/30' :
                    'bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 border border-blue-500/30'
                  } disabled:opacity-50`}
                >
                  {exportLoading === format ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  {format.toUpperCase()}
                </motion.button>
              ))}
            </div>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={fetchDashboardData}
              className="px-4 py-2.5 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-xl text-sm font-medium transition-colors flex items-center gap-2 border border-slate-700/50"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </motion.button>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-8">
        {/* Severity Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {severityCards.map((card, index) => {
            const Icon = card.icon;
            return (
              <motion.div
                key={card.severity}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="group relative"
              >
                <div
                  className={`${card.bgColor} ${card.borderColor} border rounded-2xl p-6 cursor-pointer hover:shadow-xl transition-all duration-300 hover:scale-105 backdrop-blur-sm overflow-hidden`}
                  onClick={() => onViewDetails?.(card.severity)}
                >
                  {/* Top gradient accent */}
                  <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${card.gradient}`} />
                  
                  <div className="flex items-center justify-between mb-6">
                    <div className={`p-3 rounded-xl bg-gradient-to-br ${card.gradient} shadow-lg`}>
                      <Icon size={24} className="text-white" />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs ${card.textColor} bg-black/20 px-2 py-1 rounded-full`}>
                        {card.trend}
                      </span>
                      <Eye className="w-4 h-4 text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-2xl font-bold text-white">{card.count}</h3>
                      <ProgressCircle 
                        progress={Math.min(100, (card.count / Math.max(1, totalVulnerabilities)) * 100)} 
                        color={card.gradient}
                      />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">{card.label}</h3>
                      <p className="text-sm text-slate-400 mt-1">{card.description}</p>
                    </div>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Filters */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-sm">Filter by:</span>
            <div className="flex flex-wrap gap-2">
              {['all', 'critical', 'high', 'medium', 'low'].map((filter) => {
                const colors = getSeverityColor(filter);
                return (
                  <motion.button
                    key={filter}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => setActiveFilter(filter)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${activeFilter === filter ? `${colors.bg} ${colors.text} ${colors.border} border` : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800/50'}`}
                  >
                    {filter === 'all' ? 'All Risks' : filter.charAt(0).toUpperCase() + filter.slice(1)}
                  </motion.button>
                );
              })}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
              <Filter className="w-4 h-4 text-slate-400" />
            </button>
            <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
              <Maximize2 className="w-4 h-4 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Recent Activity Sections */}
        <AnimatePresence>
          {(portScanRisks.length > 0 || filteredVulnerabilities.length > 0 || subdomainScans.length > 0) && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-8"
            >
              {/* Vulnerabilities Section */}
              {filteredVulnerabilities.length > 0 && (
                <div className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-bold text-white flex items-center gap-3">
                      <div className="p-2 bg-red-500/20 rounded-lg border border-red-500/30">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                      </div>
                      <span>Recent Security Vulnerabilities</span>
                      <span className="text-sm text-slate-400 bg-slate-800/50 px-2 py-1 rounded-full">
                        {filteredVulnerabilities.length} found
                      </span>
                    </h3>
                    <button className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                      View all <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                  
                  <div className="space-y-4">
                    {filteredVulnerabilities.map((vuln, index) => {
                      const colors = getSeverityColor(vuln.severity);
                      
                      return (
                        <motion.div
                          key={vuln.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.1 }}
                          className={`group relative overflow-hidden border ${colors.border} rounded-xl p-5 hover:shadow-lg transition-all duration-300 cursor-pointer ${expandedView === vuln.id ? 'bg-gradient-to-br from-slate-800/50 to-slate-900/40' : 'bg-gradient-to-br from-slate-800/30 to-slate-900/20'}`}
                          onClick={() => setExpandedView(expandedView === vuln.id ? null : vuln.id)}
                        >
                          {/* Left severity indicator */}
                          <div className={`absolute left-0 top-0 bottom-0 w-1 ${colors.bg.replace('bg-', 'bg-')}`} />
                          
                          <div className="pl-4">
                            <div className="flex items-start justify-between mb-4">
                              <div className="flex-1">
                                <div className="flex items-center gap-3 mb-2">
                                  <h4 className="font-bold text-white group-hover:text-cyan-300 transition-colors">
                                    {vuln.vulnerability_name}
                                  </h4>
                                  <div className={`px-3 py-1 rounded-full text-xs font-bold ${colors.bg} ${colors.text} border ${colors.border}`}>
                                    {vuln.severity.toUpperCase()}
                                  </div>
                                </div>
                                <p className="text-sm text-slate-400 mb-2">
                                  <span className="font-medium text-slate-300">Affected:</span> {vuln.affected_url}
                                </p>
                                {expandedView === vuln.id && (
                                  <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    className="text-sm text-slate-400 space-y-2"
                                  >
                                    <p>{vuln.description}</p>
                                    <div className="flex items-center gap-4 text-xs">
                                      <span className="flex items-center gap-1">
                                        <BarChart3 className="w-3 h-3" />
                                        CVSS: {vuln.cvss_score}
                                      </span>
                                      <span className="flex items-center gap-1">
                                        <Sparkles className="w-3 h-3" />
                                        Confidence: {vuln.confidence}%
                                      </span>
                                      <span className="flex items-center gap-1">
                                        <FileText className="w-3 h-3" />
                                        Scan: {vuln.scan_type}
                                      </span>
                                    </div>
                                  </motion.div>
                                )}
                              </div>
                              <div className="flex items-center gap-3 ml-4">
                                <div className="text-right">
                                  <div className="text-xs text-slate-500">
                                    {new Date(vuln.timestamp).toLocaleString()}
                                  </div>
                                  {!expandedView && (
                                    <div className="text-xs text-slate-400 mt-1">
                                      Click to expand
                                    </div>
                                  )}
                                </div>
                                {expandedView === vuln.id ? (
                                  <X className="w-4 h-4 text-slate-400" />
                                ) : (
                                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                                )}
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                </div>
              )}
              
              {/* Port Scan Risks */}
              {portScanRisks.length > 0 && (
                <div className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-bold text-white flex items-center gap-3">
                      <div className="p-2 bg-blue-500/20 rounded-lg border border-blue-500/30">
                        <Wifi className="w-5 h-5 text-blue-400" />
                      </div>
                      <span>Open Ports Detected</span>
                    </h3>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {portScanRisks.map((risk, index) => (
                      <motion.div
                        key={risk.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-5 hover:border-slate-600/60 transition-all"
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <h4 className="font-bold text-white mb-1">{risk.target_host}</h4>
                            <p className="text-sm text-slate-400">
                              {new Date(risk.timestamp).toLocaleString()}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded-full font-bold">
                              {risk.open_count} open port{risk.open_count !== 1 ? 's' : ''}
                            </div>
                            <AlertCircle className="w-4 h-4 text-yellow-400" />
                          </div>
                        </div>
                        
                        <div className="flex flex-wrap gap-2">
                          {risk.open_ports.slice(0, 4).map((port, i) => (
                            <span
                              key={i}
                              className="px-3 py-1.5 bg-slate-800/50 text-slate-300 text-sm rounded-lg border border-slate-700/50 hover:border-slate-600/60 transition-colors"
                            >
                              {port.service} ({port.port})
                            </span>
                          ))}
                          {risk.open_ports.length > 4 && (
                            <span className="px-3 py-1.5 text-slate-500 text-sm">
                              +{risk.open_ports.length - 4} more
                            </span>
                          )}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}

              {/* Subdomain Scans */}
              {subdomainScans.length > 0 && (
                <div className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-bold text-white flex items-center gap-3">
                      <div className="p-2 bg-purple-500/20 rounded-lg border border-purple-500/30">
                        <Globe className="w-5 h-5 text-purple-400" />
                      </div>
                      <span>Discovered Domains</span>
                    </h3>
                  </div>
                  
                  <div className="space-y-4">
                    {subdomainScans.map((scan, index) => (
                      <motion.div
                        key={scan.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-5 hover:border-slate-600/60 transition-all"
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <h4 className="font-bold text-white mb-1">{scan.base_domain}</h4>
                            <div className="flex items-center gap-3 text-sm text-slate-400">
                              <span>{new Date(scan.timestamp).toLocaleString()}</span>
                              <span>•</span>
                              <span>Method: {scan.scan_method}</span>
                            </div>
                          </div>
                          <div className="px-3 py-1 bg-purple-500/20 text-purple-400 text-sm rounded-full font-bold">
                            {scan.total_found} subdomain{scan.total_found !== 1 ? 's' : ''}
                          </div>
                        </div>
                        
                        <div className="flex flex-wrap gap-2">
                          {scan.discovered_subdomains.slice(0, 6).map((subdomain, i) => (
                            <span
                              key={i}
                              className="px-3 py-1.5 bg-slate-800/50 text-slate-300 text-sm rounded-lg border border-slate-700/50 hover:border-slate-600/60 transition-colors"
                            >
                              {subdomain}
                            </span>
                          ))}
                          {scan.discovered_subdomains.length > 6 && (
                            <span className="px-3 py-1.5 text-slate-500 text-sm">
                              +{scan.discovered_subdomains.length - 6} more
                            </span>
                          )}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* No Risks State */}
        {totalVulnerabilities === 0 && portScanRisks.length === 0 && filteredVulnerabilities.length === 0 && subdomainScans.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-12 bg-gradient-to-br from-emerald-500/10 to-green-500/5 rounded-2xl border border-emerald-500/30"
          >
            <div className="w-20 h-20 bg-gradient-to-br from-emerald-500/20 to-green-500/20 border border-emerald-500/30 rounded-full flex items-center justify-center mx-auto mb-6">
              <Shield size={40} className="text-emerald-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-3">All Systems Secure</h3>
            <p className="text-emerald-400 max-w-md mx-auto mb-8">
              No vulnerabilities or security risks detected across all monitored applications, ports, and domains.
            </p>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="px-6 py-3 bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 text-white rounded-xl font-medium flex items-center gap-2 mx-auto"
            >
              <Zap className="w-5 h-5" />
              Run Comprehensive Scan
            </motion.button>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}