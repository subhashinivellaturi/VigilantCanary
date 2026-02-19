import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Activity,
  Menu,
  X,
  Download,
  Zap,
  Globe,
  Settings,
  FileText,
  Search,
  Wifi,
  Eye,
  Database,
  ChevronRight,
  User,
  Sparkles,
  BarChart3,
  AlertCircle,
  Server,
  Cpu,
  RefreshCw,
  Bell,
  Filter,
  Maximize2,
  Minimize2,
  ExternalLink,
  TrendingDown
} from 'lucide-react';
import { RecentScans } from './RecentScans';
import { RecentRisks } from './RecentRisks';
import { SubdomainEnumerationPanel } from './SubdomainEnumerationPanel';
import { UnifiedReportExporter } from './UnifiedReportExporter';

interface ScanStats {
  totalScans: number;
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  lastScanTime: string;
  riskScore: number;
  openPortsCount: number;
  domainsDiscovered: number;
}

interface SystemMetric {
  name: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
}

export function DashboardProfessional() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [aiAssistantOpen, setAiAssistantOpen] = useState(false);
  const [notifications, setNotifications] = useState(3);
  const [timeSinceLastScan, setTimeSinceLastScan] = useState('Just now');
  const [fullscreenMode, setFullscreenMode] = useState<string | null>(null);

  const [stats] = useState<ScanStats>({
    totalScans: 42,
    vulnerabilitiesFound: 17,
    criticalCount: 2,
    highCount: 5,
    mediumCount: 6,
    lowCount: 4,
    lastScanTime: '2 minutes ago',
    riskScore: 78,
    openPortsCount: 23,
    domainsDiscovered: 92
  });

  const [systemMetrics] = useState<SystemMetric[]>([
    { name: 'CPU Usage', value: 42, unit: '%', trend: 'up' },
    { name: 'Memory Usage', value: 78, unit: '%', trend: 'stable' },
    { name: 'Network Traffic', value: 1.2, unit: 'GB/s', trend: 'down' },
    { name: 'Active Connections', value: 1287, unit: '', trend: 'up' }
  ]);

  const severityData = [
    {
      label: 'Critical',
      count: stats.criticalCount,
      color: 'from-red-600 via-rose-500 to-red-700',
      bgColor: 'bg-gradient-to-br from-red-500/10 to-rose-500/10',
      textColor: 'text-red-400',
      borderColor: 'border-red-500/40',
      icon: AlertCircle,
      percentage: 12,
      description: 'Immediate action required'
    },
    {
      label: 'High',
      count: stats.highCount,
      color: 'from-orange-500 via-amber-500 to-orange-700',
      bgColor: 'bg-gradient-to-br from-orange-500/10 to-amber-500/10',
      textColor: 'text-orange-400',
      borderColor: 'border-orange-500/40',
      icon: AlertTriangle,
      percentage: 63,
      description: 'Address within 24 hours'
    },
    {
      label: 'Medium',
      count: stats.mediumCount,
      color: 'from-yellow-500 via-amber-400 to-yellow-600',
      bgColor: 'bg-gradient-to-br from-yellow-500/10 to-amber-400/10',
      textColor: 'text-yellow-400',
      borderColor: 'border-yellow-500/40',
      icon: Shield,
      percentage: 75,
      description: 'Address within 1 week'
    },
    {
      label: 'Low',
      count: stats.lowCount,
      color: 'from-cyan-500 via-blue-500 to-cyan-700',
      bgColor: 'bg-gradient-to-br from-cyan-500/10 to-blue-500/10',
      textColor: 'text-cyan-400',
      borderColor: 'border-cyan-500/40',
      icon: CheckCircle,
      percentage: 50,
      description: 'Monitor and schedule fix'
    },
  ];

  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3, notification: 0 },
    { id: 'scans', label: 'Scans', icon: Search, notification: 2 },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle, notification: stats.criticalCount },
    { id: 'ports', label: 'Port Scans', icon: Wifi, notification: 0 },
    { id: 'subdomains', label: 'Subdomains', icon: Globe, notification: 0 },
    { id: 'reports', label: 'Reports', icon: FileText, notification: 0 },
    { id: 'settings', label: 'Settings', icon: Settings, notification: 0 },
  ];

  const quickStats = [
    { 
      title: 'Total Scans', 
      value: stats.totalScans, 
      icon: Activity, 
      subtitle: '+12% from last week',
      trend: 'up',
      color: 'from-blue-500 to-cyan-500'
    },
    { 
      title: 'Active Threats', 
      value: stats.vulnerabilitiesFound, 
      icon: AlertTriangle, 
      subtitle: '7 require immediate action',
      trend: 'down',
      color: 'from-red-500 to-orange-500'
    },
    { 
      title: 'Open Ports', 
      value: stats.openPortsCount, 
      icon: Wifi, 
      subtitle: 'Across all monitored assets',
      trend: 'stable',
      color: 'from-purple-500 to-pink-500'
    },
    { 
      title: 'Domains', 
      value: stats.domainsDiscovered, 
      icon: Globe, 
      subtitle: 'Active subdomains discovered',
      trend: 'up',
      color: 'from-emerald-500 to-green-500'
    }
  ];

  // Update time since last scan
  useEffect(() => {
    const interval = setInterval(() => {
      const times = ['Just now', '1 min ago', '2 mins ago', '5 mins ago'];
      const randomTime = times[Math.floor(Math.random() * times.length)];
      setTimeSinceLastScan(randomTime);
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const ProgressCircle = ({ progress, color = 'from-blue-500 to-cyan-500', size = 'medium' }: { 
    progress: number; 
    color?: string;
    size?: 'small' | 'medium' | 'large';
  }) => {
    const sizes = {
      small: 'w-12 h-12',
      medium: 'w-20 h-20',
      large: 'w-32 h-32'
    };

    const textSizes = {
      small: 'text-xs',
      medium: 'text-lg',
      large: 'text-2xl'
    };

    return (
      <div className={`relative ${sizes[size]}`}>
        <svg className={`w-full h-full transform -rotate-90`} viewBox="0 0 36 36">
          <path 
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
            fill="none" 
            stroke="rgba(255,255,255,0.1)" 
            strokeWidth="3"
            strokeLinecap="round"
          />
          <path 
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
            fill="none" 
            stroke={`url(#${color.replace(/\s+/g, '')})`}
            strokeWidth="3"
            strokeDasharray={`${progress}, 100`}
            strokeLinecap="round"
          />
          <defs>
            <linearGradient id={color.replace(/\s+/g, '')} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" style={{ stopColor: color.split(' ')[0].replace('from-', ''), stopOpacity: 1 }} />
              <stop offset="100%" style={{ stopColor: color.split(' ')[2].replace('to-', ''), stopOpacity: 1 }} />
            </linearGradient>
          </defs>
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`font-bold text-white ${textSizes[size]}`}>{progress}%</span>
        </div>
      </div>
    );
  };

  const handleRunQuickScan = () => {
    // Simulate scan action
    console.log('Quick scan initiated');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white overflow-hidden">
      {/* Animated background elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      </div>

      {/* Sidebar */}
      <motion.div
        animate={{ x: sidebarOpen ? 0 : -256 }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="fixed left-0 top-0 h-full w-64 bg-gradient-to-b from-slate-900/95 via-slate-900/95 to-slate-950/95 backdrop-blur-xl border-r border-slate-700/50 z-40 shadow-2xl"
      >
        {/* Sidebar Header */}
        <div className="p-6 border-b border-slate-700/50 bg-gradient-to-r from-blue-500/10 via-cyan-500/10 to-blue-500/10">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 via-cyan-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/50">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div className="absolute -top-1 -right-1 w-5 h-5 bg-gradient-to-br from-emerald-500 to-green-500 rounded-full border-2 border-slate-900">
                <CheckCircle className="w-3 h-3 text-white" />
              </div>
            </div>
            <div>
              <h2 className="text-white font-bold text-lg">Vigilant<span className="text-cyan-400">AI</span></h2>
              <p className="text-slate-400 text-xs">Security Platform</p>
            </div>
          </div>
        </div>

        {/* Sidebar Navigation */}
        <nav className="p-4 space-y-1 overflow-y-auto max-h-[calc(100vh-180px)]">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            return (
              <motion.button
                key={item.id}
                whileHover={{ x: 4 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => {
                  setActiveTab(item.id);
                  if (window.innerWidth < 768) setSidebarOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 relative group ${
                  activeTab === item.id
                    ? 'bg-gradient-to-r from-blue-500/30 to-cyan-500/10 text-blue-300 border-l-4 border-blue-500 shadow-lg shadow-blue-500/20'
                    : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800/50 hover:shadow-lg hover:shadow-blue-500/10'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
                {item.notification > 0 && (
                  <span className="ml-auto px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded-full font-bold min-w-6 flex items-center justify-center">
                    {item.notification}
                  </span>
                )}
                <ChevronRight className={`w-4 h-4 ml-auto transition-transform duration-300 ${
                  activeTab === item.id ? 'translate-x-0 opacity-100' : 'translate-x-2 opacity-0 group-hover:translate-x-0 group-hover:opacity-100'
                }`} />
              </motion.button>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-700/50 bg-gradient-to-t from-slate-950/90 via-slate-900/80 to-transparent">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleRunQuickScan}
            className="w-full px-4 py-3 rounded-xl bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-600 hover:from-blue-700 hover:via-cyan-700 hover:to-blue-700 text-white font-semibold transition-all shadow-lg shadow-blue-500/50 hover:shadow-blue-500/75 flex items-center justify-center gap-2"
          >
            <Zap className="w-5 h-5" />
            New Security Scan
          </motion.button>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className={`transition-all duration-300 ${sidebarOpen ? 'md:ml-64' : ''}`}>
        {/* Header */}
        <div className="sticky top-0 z-30 bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-slate-900/90 backdrop-blur-xl border-b border-slate-700/50 shadow-lg">
          <div className="px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 hover:bg-slate-800 rounded-xl transition-colors"
              >
                {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </motion.button>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  Security Intelligence Dashboard
                </h1>
                <div className="flex items-center gap-3 mt-1">
                  <div className="flex items-center gap-1 text-sm text-slate-400">
                    <Clock className="w-4 h-4" />
                    <span>Last scan: {timeSinceLastScan}</span>
                  </div>
                  <div className="flex items-center gap-1 text-sm text-slate-400">
                    <Server className="w-4 h-4" />
                    <span>42 assets monitored</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="p-2 hover:bg-slate-800 rounded-xl transition-all relative"
              >
                <Bell className="w-5 h-5 text-slate-400" />
                {notifications > 0 && (
                  <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                    {notifications}
                  </span>
                )}
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold transition-all shadow-lg shadow-blue-500/50 flex items-center gap-2"
              >
                <Sparkles className="w-5 h-5" />
                Run Smart Scan
              </motion.button>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="p-6 space-y-6">
          {/* Risk Severity Overview - Enhanced */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-white mb-1">Risk Severity Overview</h2>
                <p className="text-slate-400">Real-time vulnerability severity breakdown with threat intelligence</p>
              </div>
              <div className="flex items-center gap-2">
                <button className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/50 hover:bg-slate-800 rounded-xl text-sm text-slate-300 transition-colors">
                  <Filter className="w-4 h-4" />
                  Filter
                </button>
                <button className="p-2 hover:bg-slate-800 rounded-xl transition-colors">
                  <Maximize2 className="w-4 h-4 text-slate-400" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {severityData.map((severity, index) => {
                const Icon = severity.icon;
                return (
                  <motion.div
                    key={severity.label}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className={`group relative overflow-hidden rounded-2xl border ${severity.borderColor} bg-gradient-to-br from-slate-900/80 via-slate-900/60 to-slate-950/50 backdrop-blur-sm p-6 hover:bg-slate-900 transition-all duration-300 cursor-pointer`}
                  >
                    <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${severity.color}`}></div>

                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <p className="text-slate-400 text-sm font-medium">{severity.label}</p>
                        <p className="text-slate-500 text-xs mt-1">{severity.description}</p>
                      </div>
                      <div className={`w-12 h-12 rounded-xl ${severity.bgColor} flex items-center justify-center shadow-lg backdrop-blur-sm`}>
                        <Icon className={`w-6 h-6 ${severity.textColor}`} />
                      </div>
                    </div>

                    <div className={`text-5xl font-black ${severity.textColor} mb-3`}>{severity.count}</div>

                    <div className="flex items-center justify-between">
                      <div className={`inline-block px-4 py-1.5 rounded-full text-sm font-bold ${severity.bgColor} ${severity.textColor} border ${severity.borderColor}`}>
                        {severity.label}
                      </div>
                      <div className="text-xs text-slate-500">
                        {Math.floor((severity.count / Math.max(1, stats.vulnerabilitiesFound)) * 100)}% of total
                      </div>
                    </div>

                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden mt-4">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${severity.percentage}%` }}
                        transition={{ delay: 0.5 + index * 0.1, duration: 1 }}
                        className={`h-full bg-gradient-to-r ${severity.color}`}
                      ></motion.div>
                    </div>

                    <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-2xl"></div>
                  </motion.div>
                );
              })}
            </div>
          </motion.div>

          {/* Key Statistics & System Metrics */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            {/* Key Statistics */}
            <div className="lg:col-span-2">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {quickStats.map((stat, index) => {
                  const Icon = stat.icon;
                  return (
                    <motion.div
                      key={index}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.3 + index * 0.05 }}
                      className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 via-slate-900/40 to-slate-950/40 backdrop-blur-sm p-5 hover:bg-slate-900/80 transition-all duration-300 group"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-slate-400 text-sm font-medium">{stat.title}</p>
                          <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
                          <div className="flex items-center gap-1 mt-1">
                            <span className={`text-xs ${stat.trend === 'up' ? 'text-emerald-400' : stat.trend === 'down' ? 'text-rose-400' : 'text-amber-400'}`}>
                              {stat.trend === 'up' ? <TrendingUp className="w-3 h-3 inline mr-1" /> :
                               stat.trend === 'down' ? <TrendingDown className="w-3 h-3 inline mr-1" /> :
                               '→'}
                            </span>
                            <span className="text-xs text-slate-500">{stat.subtitle}</span>
                          </div>
                        </div>
                        <div className={`p-3 rounded-lg bg-gradient-to-br ${stat.color} shadow-lg opacity-80 group-hover:opacity-100 transition-opacity duration-300`}>
                          <Icon className="w-6 h-6 text-white" />
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* System Metrics */}
            <div className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 to-slate-950/40 backdrop-blur-sm p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-cyan-400" />
                  System Metrics
                </h3>
                <span className="text-xs text-emerald-400 bg-emerald-500/20 px-2 py-1 rounded-full">Live</span>
              </div>
              <div className="space-y-4">
                {systemMetrics.map((metric, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-400">{metric.name}</span>
                      <span className="text-sm font-semibold text-white">
                        {metric.value} {metric.unit}
                        <span className={`ml-2 text-xs ${metric.trend === 'up' ? 'text-rose-400' : metric.trend === 'down' ? 'text-emerald-400' : 'text-amber-400'}`}>
                          {metric.trend === 'up' ? '↑' : metric.trend === 'down' ? '↓' : '→'}
                        </span>
                      </span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${metric.value}%` }}
                        transition={{ delay: 0.5 + index * 0.1, duration: 1 }}
                        className={`h-full rounded-full ${
                          metric.trend === 'up' ? 'bg-gradient-to-r from-red-500 to-rose-500' :
                          metric.trend === 'down' ? 'bg-gradient-to-r from-emerald-500 to-green-500' :
                          'bg-gradient-to-r from-amber-500 to-yellow-500'
                        }`}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Recent Scans & Top Vulnerabilities */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.5 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-6"
          >
            {/* Recent Scans */}
            <div className="lg:col-span-2 rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 via-slate-900/40 to-slate-950/40 backdrop-blur-sm p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-400" />
                  Recent Scans
                </h3>
                <button className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                  View all <ChevronRight className="w-4 h-4" />
                </button>
              </div>
              <div className="bg-slate-900/40 rounded-lg p-4 -mx-6 -mb-6 overflow-hidden">
                <RecentScans />
              </div>
            </div>

            {/* Top Vulnerabilities */}
            <div className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 to-slate-950/40 backdrop-blur-sm p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  Top Vulnerabilities
                </h3>
                <span className="text-xs text-slate-400 bg-slate-800/50 px-2 py-1 rounded-full">
                  {stats.criticalCount} Critical
                </span>
              </div>
              <div className="space-y-4">
                {[
                  { title: 'SQL Injection in Login', severity: 'critical', cvss: 9.8, time: '2 hours ago' },
                  { title: 'Weak SSL Configuration', severity: 'high', cvss: 8.2, time: '1 day ago' },
                  { title: 'Exposed API Keys', severity: 'critical', cvss: 9.1, time: '3 days ago' }
                ].map((vuln, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.4 + idx * 0.05 }}
                    className="relative bg-gradient-to-br from-slate-900/60 to-slate-900/20 border border-slate-700/40 hover:border-slate-600/50 rounded-lg p-4 transition-all hover:shadow-lg hover:shadow-slate-900/40 group cursor-pointer overflow-hidden"
                  >
                    <div className={`absolute left-0 top-0 bottom-0 w-1 transition-all group-hover:w-1.5 ${
                      vuln.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'
                    }`} />

                    <div className="pl-4">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-bold text-sm text-slate-100 group-hover:text-white transition-colors flex-1">{vuln.title}</h4>
                        <div className={`px-2 py-1 rounded text-xs font-bold ${
                          vuln.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'
                        }`}>
                          {vuln.severity.toUpperCase()}
                        </div>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <div className="bg-slate-900/60 rounded px-2.5 py-1.5 border border-slate-700/40">
                          <span className="text-xs font-bold text-blue-400">CVSS {vuln.cvss}</span>
                        </div>
                        <span className="text-xs text-slate-500 font-medium">{vuln.time}</span>
                        <Eye className="w-4 h-4 text-slate-500 opacity-0 group-hover:opacity-100 group-hover:text-slate-400 transition-all" />
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Subdomains & Reports */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-6"
          >
            {/* Subdomain Enumeration */}
            <div className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 via-slate-900/40 to-slate-950/40 backdrop-blur-sm p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Globe className="w-5 h-5 text-teal-400" />
                  Subdomain Enumeration
                </h3>
                <button className="flex items-center gap-1 text-sm text-teal-400 hover:text-teal-300 transition-colors">
                  <Maximize2 className="w-4 h-4" />
                  Expand
                </button>
              </div>
              <div className="bg-slate-900/40 rounded-lg p-4">
                <SubdomainEnumerationPanel compact={true} />
              </div>
            </div>

            {/* Report Generator */}
            <div className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 via-slate-900/40 to-slate-950/40 backdrop-blur-sm p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-indigo-400" />
                  Generate Security Report
                </h3>
                <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
                  <Download className="w-4 h-4 text-slate-400" />
                </button>
              </div>
              <div className="bg-slate-900/40 rounded-lg p-4">
                <UnifiedReportExporter compact={true} />
              </div>
            </div>
          </motion.div>

          {/* Recent Risks */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            className="rounded-xl border border-slate-700/50 bg-gradient-to-br from-slate-900/50 via-slate-900/40 to-slate-950/40 backdrop-blur-sm p-6"
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-rose-400" />
                Recent Security Risks
              </h3>
              <button className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-300 transition-colors">
                View all <ExternalLink className="w-4 h-4" />
              </button>
            </div>
            <div className="bg-slate-900/40 rounded-lg p-4">
              <RecentRisks limit={5} />
            </div>
          </motion.div>
        </div>
      </div>

      {/* AI Assistant Toggle Button */}
      <motion.button
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        whileHover={{ scale: 1.1, boxShadow: '0 20px 40px rgba(59, 130, 246, 0.4)' }}
        whileTap={{ scale: 0.95 }}
        onClick={() => setAiAssistantOpen(!aiAssistantOpen)}
        className="fixed bottom-8 right-8 w-14 h-14 bg-gradient-to-br from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 rounded-full flex items-center justify-center shadow-2xl shadow-blue-500/40 z-40 group border border-blue-400/30 hover:border-blue-300/50"
      >
        <User className="w-6 h-6 text-white group-hover:scale-110 transition-transform" />
      </motion.button>

      {/* Mobile Overlay */}
      {sidebarOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 bg-black/50 z-30 md:hidden"
        ></motion.div>
      )}
    </div>
  );
}