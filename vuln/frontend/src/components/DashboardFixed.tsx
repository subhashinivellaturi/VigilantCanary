import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp, 
  Activity,
  Zap,
  Search,
  Globe,
  FileText,
  Eye,
  // ArrowUpRight,  // Not in lucide-react
  ChevronRight,
  Sparkles,
  Cpu,
  ShieldCheck,
  AlertCircle,
  TrendingDown,
  BarChart3,
  Server,
  Filter,
  Maximize2,
  Download,
  RefreshCw,
  Bell
} from 'lucide-react';

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

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;
  description: string;
  status: 'open' | 'in-progress' | 'resolved';
  timestamp: string;
}

export function Dashboard() {
  const [stats, setStats] = useState<ScanStats>({
    totalScans: 42,
    vulnerabilitiesFound: 17,
    criticalCount: 2,
    highCount: 5,
    mediumCount: 6,
    lowCount: 4,
    lastScanTime: '2 minutes ago',
    riskScore: 75,
    openPortsCount: 23,
    domainsDiscovered: 92
  });

  const [recentActivity, setRecentActivity] = useState([
    { id: 1, type: 'scan', target: 'example.com', status: 'completed', vulnerabilities: 2, time: '5 minutes ago', icon: CheckCircle },
    { id: 2, type: 'vulnerability', target: 'SQL Injection', status: 'critical', severity: 'critical', time: '12 minutes ago', icon: AlertTriangle },
    { id: 3, type: 'scan', target: 'api.example.com', status: 'completed', vulnerabilities: 0, time: '25 minutes ago', icon: CheckCircle },
    { id: 4, type: 'system', message: 'Auto-scan scheduled', status: 'info', time: '1 hour ago', icon: Clock }
  ]);

  const [vulnerabilities] = useState<Vulnerability[]>([
    { id: '1', title: 'SQL Injection in Login Form', severity: 'critical', cvss: 9.8, description: 'Unsanitized input allows SQL injection', status: 'open', timestamp: '2 hours ago' },
    { id: '2', title: 'Weak SSL/TLS Configuration', severity: 'high', cvss: 8.2, description: 'Outdated TLS 1.1 detected', status: 'open', timestamp: '1 day ago' },
    { id: '3', title: 'Exposed API Keys', severity: 'critical', cvss: 9.1, description: 'API keys exposed in public repository', status: 'in-progress', timestamp: '3 days ago' },
    { id: '4', title: 'Cross-Site Scripting (XSS)', severity: 'medium', cvss: 6.5, description: 'Reflected XSS in search parameter', status: 'open', timestamp: '5 hours ago' }
  ]);

  const quickStats = [
    { 
      title: 'Total Scans', 
      value: stats.totalScans, 
      icon: Search, 
      subtitle: '+12% from last week',
      trend: 'up',
      color: 'from-blue-500 to-cyan-500',
      bgColor: 'bg-gradient-to-br from-blue-500/10 to-cyan-500/10'
    },
    { 
      title: 'Active Threats', 
      value: stats.vulnerabilitiesFound, 
      icon: AlertTriangle, 
      subtitle: '7 require immediate action',
      trend: 'down',
      color: 'from-red-500 to-orange-500',
      bgColor: 'bg-gradient-to-br from-red-500/10 to-orange-500/10'
    },
    { 
      title: 'Last Scan', 
      value: stats.lastScanTime, 
      icon: Clock, 
      subtitle: 'System updated',
      trend: 'stable',
      color: 'from-purple-500 to-pink-500',
      bgColor: 'bg-gradient-to-br from-purple-500/10 to-pink-500/10'
    },
    { 
      title: 'Security Score', 
      value: `${stats.riskScore}/100`, 
      icon: ShieldCheck, 
      subtitle: 'Better than 85% of peers',
      trend: 'up',
      color: 'from-emerald-500 to-green-500',
      bgColor: 'bg-gradient-to-br from-emerald-500/10 to-green-500/10'
    }
  ];

  const severityCards = [
    { 
      label: 'Critical', 
      count: stats.criticalCount, 
      color: 'from-red-600 to-rose-600',
      icon: AlertCircle,
      percentage: Math.floor((stats.criticalCount / Math.max(1, stats.vulnerabilitiesFound)) * 100),
      description: 'Immediate action required'
    },
    { 
      label: 'High', 
      count: stats.highCount, 
      color: 'from-orange-500 to-amber-500',
      icon: AlertTriangle,
      percentage: Math.floor((stats.highCount / Math.max(1, stats.vulnerabilitiesFound)) * 100),
      description: 'Address within 24 hours'
    },
    { 
      label: 'Medium', 
      count: stats.mediumCount, 
      color: 'from-yellow-500 to-amber-400',
      icon: Shield,
      percentage: Math.floor((stats.mediumCount / Math.max(1, stats.vulnerabilitiesFound)) * 100),
      description: 'Address within 1 week'
    },
    { 
      label: 'Low', 
      count: stats.lowCount, 
      color: 'from-emerald-500 to-teal-500',
      icon: CheckCircle,
      percentage: Math.floor((stats.lowCount / Math.max(1, stats.vulnerabilitiesFound)) * 100),
      description: 'Monitor and schedule fix'
    }
  ];

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

  // Simulate live updates
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        lastScanTime: ['Just now', '1 min ago', '2 mins ago', '5 mins ago'][Math.floor(Math.random() * 4)]
      }));
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const runQuickScan = () => {
    // Simulate scan action
    setRecentActivity(prev => [
      {
        id: Date.now(),
        type: 'scan',
        target: 'quick-scan.example.com',
        status: 'running',
        vulnerabilities: 0,
        time: 'Just now',
        icon: Activity
      },
      ...prev.slice(0, 3)
    ]);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 p-6">
      {/* Main Content Container */}
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Hero Header with Modern Design */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-600/20 via-purple-600/20 to-indigo-700/20 border border-slate-700/50 backdrop-blur-sm"
        >
          {/* Animated background elements */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full -translate-y-32 translate-x-32" />
          <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-500/5 rounded-full -translate-x-48 translate-y-48" />
          
          <div className="relative z-10 p-8">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
              <div className="flex-1">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl shadow-lg">
                    <Shield className="h-8 w-8 text-white" />
                  </div>
                  <div>
                    <h1 className="text-3xl lg:text-4xl font-bold bg-gradient-to-r from-blue-400 via-cyan-300 to-purple-400 bg-clip-text text-transparent">
                      Vigilant Security Dashboard
                    </h1>
                    <p className="text-slate-300 mt-2">
                      Real-time threat intelligence & vulnerability management platform
                    </p>
                  </div>
                </div>

                {/* Quick Stats Grid */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
                  {quickStats.map((stat, index) => (
                    <motion.div
                      key={stat.title}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className={`${stat.bgColor} backdrop-blur-sm border border-slate-700/30 rounded-xl p-4 hover:scale-[1.02] transition-all duration-300 hover:shadow-lg`}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className={`p-2 rounded-lg bg-gradient-to-br ${stat.color}`}>
                          <stat.icon className="h-5 w-5 text-white" />
                        </div>
                        {stat.trend === 'up' && <TrendingUp className="h-4 w-4 text-emerald-400" />}
                        {stat.trend === 'down' && <TrendingDown className="h-4 w-4 text-rose-400" />}
                      </div>
                      <div>
                        <p className="text-slate-400 text-sm font-medium">{stat.title}</p>
                        <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                        <p className="text-slate-500 text-xs mt-1">{stat.subtitle}</p>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>

              {/* Risk Score Circle */}
              <motion.div 
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 200, delay: 0.3 }}
                className="flex flex-col items-center"
              >
                <div className="relative">
                  <ProgressCircle progress={stats.riskScore} color="from-cyan-500 to-blue-500" size="large" />
                  <div className="absolute -top-2 -right-2">
                    <div className="bg-gradient-to-r from-emerald-500 to-green-500 text-white text-xs font-bold px-2 py-1 rounded-full">
                      {stats.riskScore >= 80 ? 'Excellent' : stats.riskScore >= 60 ? 'Good' : 'Needs Attention'}
                    </div>
                  </div>
                </div>
                <p className="text-slate-300 text-sm mt-4 text-center">Overall Security Score</p>
              </motion.div>
            </div>

            {/* Quick Actions */}
            <div className="flex flex-wrap gap-3 mt-8">
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={runQuickScan}
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl font-medium hover:shadow-lg transition-all duration-300 group"
              >
                <Zap className="h-5 w-5 group-hover:rotate-12 transition-transform" />
                Run Quick Scan
                {/* <ArrowUpRight className="h-4 w-4 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" /> */}
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex items-center gap-2 px-6 py-3 bg-slate-800/50 text-slate-200 border border-slate-700 rounded-xl font-medium hover:bg-slate-700/50 transition-all duration-300"
              >
                <Eye className="h-5 w-5" />
                View Critical Issues
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex items-center gap-2 px-6 py-3 bg-slate-800/50 text-slate-200 border border-slate-700 rounded-xl font-medium hover:bg-slate-700/50 transition-all duration-300"
              >
                <FileText className="h-5 w-5" />
                Generate Report
              </motion.button>
            </div>
          </div>
        </motion.div>

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Risk Severity */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="lg:col-span-2 space-y-6"
          >
            {/* Risk Severity Cards */}
            <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold text-white mb-1">Risk Severity Overview</h2>
                  <p className="text-slate-400 text-sm">Real-time vulnerability severity breakdown</p>
                </div>
                <div className="flex items-center gap-2">
                  <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
                    <Filter className="h-4 w-4 text-slate-400" />
                  </button>
                  <button className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
                    <Maximize2 className="h-4 w-4 text-slate-400" />
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {severityCards.map((card, index) => {
                  const Icon = card.icon;
                  return (
                    <motion.div
                      key={card.label}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className={`bg-gradient-to-br ${card.color}/10 backdrop-blur-sm border border-slate-700/30 rounded-xl p-5 hover:scale-[1.02] transition-all duration-300`}
                    >
                      <div className="flex items-center justify-between mb-4">
                        <div className={`p-3 rounded-lg bg-gradient-to-br ${card.color}`}>
                          <Icon className="h-6 w-6 text-white" />
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-2xl font-bold text-white">{card.count}</span>
                          <span className="text-slate-400 text-sm">findings</span>
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-lg font-semibold text-white">{card.label}</h3>
                          <p className="text-slate-400 text-sm mt-1">{card.description}</p>
                        </div>
                        <ProgressCircle progress={card.percentage} color={card.color} size="small" />
                      </div>
                      <div className="mt-4 pt-4 border-t border-slate-700/30">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Percentage of total</span>
                          <span className="font-semibold text-white">{card.percentage}%</span>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* Recent Activity Enhanced */}
            <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold text-white mb-1">Recent Activity</h2>
                  <p className="text-slate-400 text-sm">Latest security scan results and events</p>
                </div>
                <button className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                  View all <ChevronRight className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-3">
                {recentActivity.map((activity, index) => {
                  const Icon = activity.icon;
                  return (
                    <motion.div
                      key={activity.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group cursor-pointer"
                    >
                      <div className="flex items-center gap-4">
                        <div className={`p-3 rounded-lg ${
                          activity.status === 'completed' ? 'bg-green-500/20' :
                          activity.status === 'critical' ? 'bg-red-500/20' :
                          activity.status === 'running' ? 'bg-blue-500/20' :
                          'bg-slate-500/20'
                        }`}>
                          <Icon className={`h-5 w-5 ${
                            activity.status === 'completed' ? 'text-green-400' :
                            activity.status === 'critical' ? 'text-red-400' :
                            activity.status === 'running' ? 'text-blue-400' :
                            'text-slate-400'
                          }`} />
                        </div>
                        <div>
                          <p className="font-medium text-white group-hover:text-blue-300 transition-colors">
                            {activity.type === 'scan' ? `Scan ${activity.status}: ${activity.target}` :
                             activity.type === 'vulnerability' ? `Critical vulnerability detected: ${activity.target}` :
                             activity.message}
                          </p>
                          <div className="flex items-center gap-3 mt-1">
                            <p className="text-xs text-slate-400">
                              {activity.type === 'scan' && `${activity.vulnerabilities} vulnerabilities found • `}
                              {activity.time}
                            </p>
                            {activity.status === 'running' && (
                              <div className="flex items-center gap-1">
                                <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                                <span className="text-xs text-blue-400">Live</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors opacity-0 group-hover:opacity-100" />
                    </motion.div>
                  );
                })}
              </div>
            </div>
          </motion.div>

          {/* Right Column - Critical Issues & Quick Tools */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="space-y-6"
          >
            {/* Top Vulnerabilities */}
            <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  Critical Findings
                </h3>
                <span className="text-xs text-slate-400 bg-slate-800/50 px-2 py-1 rounded-full">
                  {vulnerabilities.filter(v => v.severity === 'critical').length} Critical
                </span>
              </div>

              <div className="space-y-4">
                {vulnerabilities.slice(0, 3).map((vuln) => (
                  <motion.div
                    key={vuln.id}
                    whileHover={{ x: 4 }}
                    className="p-4 rounded-xl bg-gradient-to-br from-slate-800/30 to-slate-800/10 border border-slate-700/30 hover:border-slate-600/50 transition-all duration-300 cursor-pointer group"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <p className="font-semibold text-white group-hover:text-red-300 transition-colors">{vuln.title}</p>
                        <p className="text-sm text-slate-400 mt-1 line-clamp-2">{vuln.description}</p>
                      </div>
                      <div
                        className={`px-3 py-1 rounded-full text-xs font-bold whitespace-nowrap ml-2 ${
                          vuln.severity === 'critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : vuln.severity === 'high'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                        }`}
                      >
                        CVSS {vuln.cvss}
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {vuln.timestamp}
                      </span>
                      <div className={`px-2 py-1 rounded text-xs ${
                        vuln.status === 'open' ? 'bg-red-500/20 text-red-400' :
                        vuln.status === 'in-progress' ? 'bg-blue-500/20 text-blue-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {vuln.status === 'in-progress' ? 'In Progress' : vuln.status}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Quick Tools */}
            <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                Quick Security Tools
              </h3>
              
              <div className="space-y-3">
                <motion.button
                  whileHover={{ x: 4 }}
                  className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-lg">
                      <Globe className="h-5 w-5 text-cyan-400" />
                    </div>
                    <div className="text-left">
                      <p className="font-medium text-white">Subdomain Scanner</p>
                      <p className="text-xs text-slate-400">Discover all subdomains</p>
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors" />
                </motion.button>

                <motion.button
                  whileHover={{ x: 4 }}
                  className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-lg">
                      <Download className="h-5 w-5 text-purple-400" />
                    </div>
                    <div className="text-left">
                      <p className="font-medium text-white">Generate Report</p>
                      <p className="text-xs text-slate-400">Export security assessment</p>
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors" />
                </motion.button>

                <motion.button
                  whileHover={{ x: 4 }}
                  className="w-full flex items-center justify-between p-4 bg-slate-800/30 hover:bg-slate-700/50 border border-slate-700/30 rounded-xl transition-all duration-300 group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gradient-to-br from-emerald-500/20 to-green-500/20 rounded-lg">
                      <Sparkles className="h-5 w-5 text-emerald-400" />
                    </div>
                    <div className="text-left">
                      <p className="font-medium text-white">AI Security Assistant</p>
                      <p className="text-xs text-slate-400">Get remediation advice</p>
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-slate-400 group-hover:text-white transition-colors" />
                </motion.button>
              </div>
            </div>

            {/* System Status */}
            <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-bold text-white">System Status</h3>
                  <p className="text-slate-400 text-sm">All systems operational</p>
                </div>
                <div className="flex items-center gap-2 bg-emerald-500/20 text-emerald-400 px-3 py-1 rounded-full text-sm font-medium">
                  <div className="h-2 w-2 bg-emerald-400 rounded-full animate-pulse" />
                  Online
                </div>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">Scanner Engine</span>
                  <span className="text-emerald-400">✓ Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">AI Detector</span>
                  <span className="text-emerald-400">✓ Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">Database</span>
                  <span className="text-emerald-400">✓ Connected</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">API Services</span>
                  <span className="text-emerald-400">✓ Running</span>
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Bottom Section - Additional Info */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 rounded-2xl p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-bold text-white">Security Insights</h3>
              <p className="text-slate-400 text-sm">Automated recommendations based on scan data</p>
            </div>
            <RefreshCw className="h-5 w-5 text-slate-400" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { title: 'Enable WAF Protection', description: 'Web Application Firewall not detected', priority: 'high' },
              { title: 'Update SSL Certificates', description: '2 certificates expiring in 30 days', priority: 'medium' },
              { title: 'Implement Rate Limiting', description: 'No rate limiting on API endpoints', priority: 'low' }
            ].map((insight, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 + index * 0.1 }}
                className="p-4 bg-slate-800/30 border border-slate-700/30 rounded-xl hover:border-slate-600/50 transition-all"
              >
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold text-white">{insight.title}</h4>
                  <div className={`px-2 py-1 rounded text-xs ${
                    insight.priority === 'high' ? 'bg-red-500/20 text-red-400' :
                    insight.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-blue-500/20 text-blue-400'
                  }`}>
                    {insight.priority.toUpperCase()}
                  </div>
                </div>
                <p className="text-sm text-slate-400">{insight.description}</p>
                <button className="mt-3 text-sm text-blue-400 hover:text-blue-300 transition-colors">
                  Configure →
                </button>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}