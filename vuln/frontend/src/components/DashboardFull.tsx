import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Activity,
  Zap,
  Search,
  Globe,
  FileText,
  Eye,
  Download,
  Settings,
  RefreshCw,
  BarChart3,
  Server,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Wifi,
  Filter,
  Maximize2,
  Bell,
  AlertCircle,
  Cpu,
  Database
} from 'lucide-react';
import { RecentScans } from './RecentScans';
import { PortScanner } from './PortScanner';
import { SubdomainFinder } from './SubdomainFinder';
import { API_URL } from '../api/client';
import { generateUnifiedSecurityReport } from '../utils/pdfGenerator';
import '../styles/dashboard-full.css';

type Counts = { critical: number; high: number; medium: number; low: number };

export function DashboardFull() {
  const [counts, setCounts] = useState<Counts>({ critical: 12, high: 28, medium: 45, low: 67 });
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState('dashboard');
  const [scanning, setScanning] = useState(false);
  const [notifications] = useState(5);
  const [securityScore] = useState(78);

  useEffect(() => {
    fetchSummary();
    const interval = setInterval(fetchSummary, 30000);
    return () => clearInterval(interval);
  }, []);

  async function fetchSummary() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_URL}/dashboard/summary`);
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const data = await res.json();
      const cvss = data.cvss_counts || data.stored_counts || data;
      setCounts({
        critical: cvss.critical ?? 0,
        high: cvss.high ?? 0,
        medium: cvss.medium ?? 0,
        low: cvss.low ?? 0,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  const handleQuickScan = () => {
    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      setCounts(prev => ({
        ...prev,
        critical: prev.critical + 1,
        high: prev.high + 2
      }));
    }, 2000);
  };

  const handleGenerateReport = async (format: 'pdf' | 'csv' | 'json') => {
    try {
      await generateUnifiedSecurityReport(format);
    } catch (e) {
      alert(`Export failed: ${e}`);
    }
  };

  const totalRisks = counts.critical + counts.high + counts.medium + counts.low;

  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'scanner', label: 'Vulnerability Scanner', icon: Search },
    { id: 'port-scanner', label: 'Port Scanner', icon: Wifi },
    { id: 'subdomain-finder', label: 'Subdomain Finder', icon: Globe },
    { id: 'recent-scans', label: 'Scan History', icon: Activity },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  const recentRisks = [
    { id: 1, severity: 'CRITICAL', title: 'SQL Injection Vulnerability', target: 'https://api.example.com/users?id=1', time: '10 minutes ago' },
    { id: 2, severity: 'HIGH', title: 'XSS in Contact Form', target: 'https://example.com/contact', time: '25 minutes ago' },
    { id: 3, severity: 'MEDIUM', title: 'Outdated TLS Version', target: 'https://api.example.com', time: '2 hours ago' },
    { id: 4, severity: 'CRITICAL', title: 'Exposed API Keys', target: 'GitHub Repository', time: '1 day ago' }
  ];

  const portScanResults = [
    { port: 80, service: 'HTTP', state: 'OPEN', protocol: 'TCP' },
    { port: 443, service: 'HTTPS', state: 'OPEN', protocol: 'TCP' },
    { port: 22, service: 'SSH', state: 'OPEN', protocol: 'TCP' },
    { port: 3306, service: 'MySQL', state: 'OPEN', protocol: 'TCP' },
    { port: 5432, service: 'PostgreSQL', state: 'CLOSED', protocol: 'TCP' },
    { port: 8080, service: 'HTTP-ALT', state: 'FILTERED', protocol: 'TCP' }
  ];

  const ProgressCircle = ({ progress, color = 'from-blue-500 to-cyan-500' }: { progress: number; color?: string }) => (
    <div className="relative w-16 h-16">
      <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
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
        <span className="text-lg font-bold text-white">{progress}%</span>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 text-white overflow-hidden">
      {/* Animated Background Elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      </div>

      {/* Modern Sidebar */}
      <motion.aside
        initial={{ x: -280 }}
        animate={{ x: sidebarOpen ? 0 : -280 }}
        className="fixed left-0 top-0 h-full w-72 bg-gradient-to-b from-slate-900/95 to-slate-950/95 backdrop-blur-xl border-r border-slate-700/50 z-40 shadow-2xl"
      >
        <div className="p-6 border-b border-slate-700/50">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 via-cyan-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/50">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="text-white font-bold text-lg">Vigilant</h2>
              <p className="text-slate-400 text-xs">Security Intelligence Platform</p>
            </div>
          </div>
        </div>

        <nav className="p-4 space-y-1">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            return (
              <motion.button
                key={item.id}
                whileHover={{ x: 4 }}
                onClick={() => setActiveSection(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${
                  activeSection === item.id
                    ? 'bg-gradient-to-r from-blue-500/30 to-cyan-500/10 text-blue-300 border-l-4 border-blue-500 shadow-lg shadow-blue-500/20'
                    : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </motion.button>
            );
          })}
        </nav>

        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-700/50 bg-gradient-to-t from-slate-950 to-transparent">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleQuickScan}
            className="w-full px-4 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold transition-all shadow-lg shadow-blue-500/50 hover:shadow-blue-500/75 flex items-center justify-center gap-2"
          >
            <Zap className="w-5 h-5" />
            New Security Scan
          </motion.button>
        </div>
      </motion.aside>

      {/* Main Content */}
      <div className={`${sidebarOpen ? 'md:ml-72' : ''} transition-all duration-300`}>
        {/* Header */}
        <div className="sticky top-0 z-30 bg-slate-900/80 backdrop-blur-xl border-b border-slate-700/50 shadow-lg">
          <div className="px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
              >
                {sidebarOpen ? '✕' : '☰'}
              </motion.button>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                  Security Intelligence Dashboard
                </h1>
                <p className="text-sm text-slate-400">Real-time threat intelligence & vulnerability management</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={fetchSummary}
                disabled={loading}
                className="px-4 py-2 rounded-lg bg-slate-800/50 hover:bg-slate-700 text-slate-300 font-medium transition-all flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                {loading ? 'Refreshing...' : 'Refresh'}
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold transition-all shadow-lg shadow-blue-500/50"
              >
                ▶ Run Scan
              </motion.button>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="p-6 space-y-6">
          {/* Risk Severity Overview */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6"
          >
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-white mb-1">Risk Severity Overview</h2>
                <p className="text-slate-400">Real-time vulnerability severity breakdown with threat intelligence</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="px-3 py-1.5 bg-slate-800/50 rounded-lg text-sm text-slate-300">
                  Total Risks: {totalRisks}
                </div>
                <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
                  <Filter className="w-4 h-4 text-slate-400" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'Critical', count: counts.critical, color: 'from-red-600 to-rose-600', icon: AlertCircle, trend: '+3 today' },
                { label: 'High', count: counts.high, color: 'from-orange-500 to-amber-500', icon: AlertTriangle, trend: '+5 today' },
                { label: 'Medium', count: counts.medium, color: 'from-yellow-500 to-amber-400', icon: Shield, trend: '+8 today' },
                { label: 'Low', count: counts.low, color: 'from-emerald-500 to-teal-500', icon: CheckCircle, trend: '+12 today' }
              ].map((severity, index) => {
                const Icon = severity.icon;
                return (
                  <motion.div
                    key={severity.label}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className={`group relative overflow-hidden rounded-xl border border-slate-700/30 bg-gradient-to-br from-slate-900/80 to-slate-950/50 backdrop-blur-sm p-5 hover:bg-slate-900 transition-all cursor-pointer`}
                  >
                    <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${severity.color}`}></div>
                    
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <p className="text-slate-400 text-sm font-medium">{severity.label}</p>
                        <p className="text-slate-500 text-xs mt-1">Immediate action required</p>
                      </div>
                      <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${severity.color}/10 flex items-center justify-center`}>
                        <Icon className={`w-6 h-6 ${
                          severity.label === 'Critical' ? 'text-red-400' :
                          severity.label === 'High' ? 'text-orange-400' :
                          severity.label === 'Medium' ? 'text-yellow-400' :
                          'text-emerald-400'
                        }`} />
                      </div>
                    </div>

                    <div className={`text-5xl font-bold mb-3 ${
                      severity.label === 'Critical' ? 'text-red-400' :
                      severity.label === 'High' ? 'text-orange-400' :
                      severity.label === 'Medium' ? 'text-yellow-400' :
                      'text-emerald-400'
                    }`}>{severity.count}</div>

                    <div className="flex items-center justify-between">
                      <div className={`inline-block px-3 py-1 rounded-full text-xs font-bold bg-gradient-to-br ${severity.color}/20 ${
                        severity.label === 'Critical' ? 'text-red-400 border border-red-500/30' :
                        severity.label === 'High' ? 'text-orange-400 border border-orange-500/30' :
                        severity.label === 'Medium' ? 'text-yellow-400 border border-yellow-500/30' :
                        'text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {severity.label}
                      </div>
                      <div className="text-xs text-slate-500">{severity.trend}</div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </motion.section>

          {/* Recent Scans & System Status */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Recent Scans */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="lg:col-span-2 bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-400" />
                  Recent Scans
                </h3>
                <button className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                  View all <ExternalLink className="w-4 h-4" />
                </button>
              </div>
              <div className="overflow-hidden">
                <RecentScans limit={5} />
              </div>
            </motion.div>

            {/* System Status & Quick Actions */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
              className="space-y-6"
            >
              {/* Security Score */}
              <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6 flex flex-col items-center justify-center">
                <h3 className="text-lg font-bold text-white mb-4">Security Score</h3>
                <ProgressCircle progress={securityScore} color="from-cyan-500 to-blue-500" />
                <p className="text-slate-400 text-sm mt-4">Overall security posture</p>
                <div className="mt-3 px-3 py-1 bg-emerald-500/20 text-emerald-400 text-sm rounded-full">
                  {securityScore >= 80 ? 'Excellent' : securityScore >= 60 ? 'Good' : 'Needs Improvement'}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6">
                <h3 className="text-lg font-bold text-white mb-4">Quick Actions</h3>
                <div className="space-y-3">
                  <motion.button
                    whileHover={{ x: 4 }}
                    className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-lg">
                        <Zap className="h-5 w-5 text-cyan-400" />
                      </div>
                      <div className="text-left">
                        <p className="font-medium text-white">Run Quick Scan</p>
                        <p className="text-xs text-slate-400">Scan all assets</p>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors" />
                  </motion.button>

                  <motion.button
                    whileHover={{ x: 4 }}
                    onClick={() => handleGenerateReport('pdf')}
                    className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-lg">
                        <Download className="h-5 w-5 text-purple-400" />
                      </div>
                      <div className="text-left">
                        <p className="font-medium text-white">Export Report</p>
                        <p className="text-xs text-slate-400">Generate security report</p>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors" />
                  </motion.button>
                </div>
              </div>
            </motion.div>
          </div>

          {/* Port Scanner & Recent Risks */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Port Scanner */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <Wifi className="w-5 h-5 text-purple-400" />
                  Port Scanner
                </h3>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Enter IP or domain..."
                    className="px-3 py-1.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50"
                  />
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    className="px-4 py-1.5 bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm rounded-lg font-medium"
                  >
                    Scan
                  </motion.button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {portScanResults.map((port, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.4 + idx * 0.05 }}
                    className={`p-4 rounded-xl border ${
                      port.state === 'OPEN' 
                        ? 'border-green-500/30 bg-green-500/10' 
                        : port.state === 'CLOSED'
                        ? 'border-red-500/30 bg-red-500/10'
                        : 'border-yellow-500/30 bg-yellow-500/10'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-lg text-white">:{port.port}</span>
                      <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                        port.state === 'OPEN' 
                          ? 'bg-green-500/20 text-green-400' 
                          : port.state === 'CLOSED'
                          ? 'bg-red-500/20 text-red-400'
                          : 'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {port.state}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400">{port.service}</p>
                    <p className="text-xs text-slate-500 mt-1">{port.protocol}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Recent Risks */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-6"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  Recent Risks
                </h3>
                <button className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-300 transition-colors">
                  View all <ExternalLink className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-4">
                {recentRisks.map((risk) => (
                  <motion.div
                    key={risk.id}
                    whileHover={{ x: 4 }}
                    className="p-4 rounded-xl bg-gradient-to-br from-slate-800/30 to-slate-800/10 border border-slate-700/30 hover:border-slate-600/50 transition-all duration-300 cursor-pointer group"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <p className="font-semibold text-white group-hover:text-red-300 transition-colors">{risk.title}</p>
                        <p className="text-sm text-slate-400 mt-1 line-clamp-1">{risk.target}</p>
                      </div>
                      <div
                        className={`px-3 py-1 rounded-full text-xs font-bold whitespace-nowrap ml-2 ${
                          risk.severity === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : risk.severity === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}
                      >
                        {risk.severity}
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {risk.time}
                      </span>
                      <Eye className="w-4 h-4 text-slate-400 opacity-0 group-hover:opacity-100 group-hover:text-slate-300 transition-all" />
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>

          {/* Report Generator */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="bg-gradient-to-r from-slate-800/50 via-indigo-900/30 to-slate-800/50 border border-slate-700/50 rounded-2xl p-6"
          >
            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-indigo-400" />
              Generate Security Report
            </h3>
            <p className="text-slate-400 mb-6">Export comprehensive security assessment in multiple formats</p>
            
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2">
                <input type="checkbox" id="include-vulns" defaultChecked className="accent-blue-500" />
                <label htmlFor="include-vulns" className="text-slate-300">Include Vulnerabilities</label>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="include-ports" defaultChecked className="accent-blue-500" />
                <label htmlFor="include-ports" className="text-slate-300">Include Open Ports</label>
              </div>
              <select className="px-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-white focus:outline-none focus:border-blue-500/50">
                <option value="pdf">PDF Format</option>
                <option value="csv">CSV Format</option>
                <option value="json">JSON Format</option>
              </select>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => handleGenerateReport('pdf')}
                className="px-6 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-lg transition-all shadow-lg shadow-blue-500/50 flex items-center gap-2"
              >
                <Download className="w-5 h-5" />
                Generate Report
              </motion.button>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Error Toast */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className="fixed bottom-6 right-6 bg-red-500/20 border border-red-500/30 text-red-400 px-6 py-3 rounded-xl shadow-lg backdrop-blur-sm z-50"
          >
            <div className="flex items-center gap-3">
              <AlertCircle className="w-5 h-5" />
              <div>
                <p className="font-semibold">Error fetching data</p>
                <p className="text-sm">{error}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}