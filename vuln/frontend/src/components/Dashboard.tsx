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
  FileText,
  Globe,
  BarChart3,
  Eye,
  // ArrowUpRight,  // Not in lucide-react
  ChevronRight,
  Sparkles,
  Cpu,
  ShieldCheck,
  AlertCircle,
  TrendingDown
} from 'lucide-react';
import { RecentScans } from './RecentScans';
import { RecentRisks } from './RecentRisks';
import { SubdomainEnumerationPanel } from './SubdomainEnumerationPanel';
import { SubdomainScanHistory } from './SubdomainScanHistory';
import { UnifiedReportExporter } from './UnifiedReportExporter';
import { Card } from './ui/Card';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/vulnerabilities/summary');
      const data = await res.json();
      setStats(data);
    } catch {
      setStats(null);
    }
  };

  useEffect(() => {
    fetchStats();
    const handler = () => fetchStats();
    window.addEventListener('scanCompleted', handler);
    return () => window.removeEventListener('scanCompleted', handler);
  }, []);

  const quickStats = stats ? [
    { 
      title: 'Total Scans', 
      value: stats.total_scans, 
      icon: Search, 
      subtitle: '',
      trend: 'up',
      color: 'from-blue-500 to-cyan-500',
      bgColor: 'bg-gradient-to-br from-blue-500/10 to-cyan-500/10'
    },
    { 
      title: 'Active Threats', 
      value: stats.total_vulnerabilities, 
      icon: AlertTriangle, 
      subtitle: '',
      trend: 'down',
      color: 'from-red-500 to-orange-500',
      bgColor: 'bg-gradient-to-br from-red-500/10 to-orange-500/10'
    },
    { 
      title: 'Last Scan', 
      value: stats.last_scan_time, 
      icon: Clock, 
      subtitle: '',
      trend: 'stable',
      color: 'from-purple-500 to-pink-500',
      bgColor: 'bg-gradient-to-br from-purple-500/10 to-pink-500/10'
    },
    { 
      title: 'Security Score', 
      value: `${stats.risk_score}/100`, 
      icon: ShieldCheck, 
      subtitle: '',
      trend: 'up',
      color: 'from-emerald-500 to-green-500',
      bgColor: 'bg-gradient-to-br from-emerald-500/10 to-green-500/10'
    }
  ] : [];

  const severityCards = stats ? [
    { 
      label: 'Critical', 
      count: stats.critical_count, 
      color: 'from-red-600 to-rose-600',
      icon: AlertCircle,
      percentage: Math.floor((stats.critical_count / Math.max(1, stats.total_vulnerabilities)) * 100),
      trend: 'up'
    },
    { 
      label: 'High', 
      count: stats.high_count, 
      color: 'from-orange-500 to-amber-500',
      icon: AlertTriangle,
      percentage: Math.floor((stats.high_count / Math.max(1, stats.total_vulnerabilities)) * 100),
      trend: 'stable'
    },
    { 
      label: 'Medium', 
      count: stats.medium_count, 
      color: 'from-yellow-500 to-amber-400',
      icon: Shield,
      percentage: Math.floor((stats.medium_count / Math.max(1, stats.total_vulnerabilities)) * 100),
      trend: 'down'
    },
    { 
      label: 'Low', 
      count: stats.low_count, 
      color: 'from-emerald-500 to-teal-500',
      icon: CheckCircle,
      percentage: Math.floor((stats.low_count / Math.max(1, stats.total_vulnerabilities)) * 100),
      trend: 'down'
    }
  ] : [];

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

    const strokeWidth = {
      small: 2,
      medium: 3,
      large: 4
    };

    return (
      <div className={`relative ${sizes[size]}`}>
        <svg className={`w-full h-full transform -rotate-90`} viewBox="0 0 36 36">
          <path 
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
            fill="none" 
            stroke="rgba(255,255,255,0.1)" 
            strokeWidth={strokeWidth[size]}
            strokeLinecap="round"
          />
          <path 
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
            fill="none" 
            stroke={`url(#${color.replace(/\s+/g, '')})`}
            strokeWidth={strokeWidth[size]}
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

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 p-4 md:p-6">
      {/* Skip link for accessibility */}
      <a href="#dashboard-content" className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:bg-gradient-to-r focus:from-blue-600 focus:to-purple-600 focus:text-white px-4 py-2 rounded-lg font-medium shadow-lg transition-all">
        Skip to dashboard content
      </a>

      <div id="dashboard-content" className="max-w-7xl mx-auto space-y-6">
        {/* Hero Header */}
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-800 via-slate-900 to-slate-950 border border-slate-700/50 shadow-2xl"
        >
          {/* ...existing code for header and quick stats... */}
          <div className="relative z-10 p-8">
            {/* ...existing code for header ... */}
          </div>
        </motion.div>

        {/* Responsive 3-column grid for all dashboard sections */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Risk Severity Overview */}
          <Card
            title="Risk Severity Overview"
            subtitle="Real-time vulnerability severity breakdown"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <div className="grid grid-cols-1 gap-4">
                {severityCards.map((card, index) => (
                  <motion.div
                    key={card.label}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className={`bg-gradient-to-br ${card.color}/10 backdrop-blur-sm border border-slate-700/30 rounded-xl p-5 hover:scale-[1.02] transition-all duration-300`}
                  >
                    {/* ...existing code for severity card... */}
                    <div className="flex items-center justify-between mb-4">
                      <div className={`p-3 rounded-lg bg-gradient-to-br ${card.color}`}>
                        <card.icon className="h-6 w-6 text-white" />
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-2xl font-bold text-white">{card.count}</span>
                        <span className="text-slate-400 text-sm">findings</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-semibold text-white">{card.label}</h3>
                        <p className="text-slate-400 text-sm mt-1">{card.percentage}% of total</p>
                      </div>
                      <ProgressCircle progress={card.percentage} color={card.color} size="small" />
                    </div>
                    <div className="mt-4 pt-4 border-t border-slate-700/30">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Trend</span>
                        <span className={`flex items-center gap-1 ${
                          card.trend === 'up' ? 'text-rose-400' :
                          card.trend === 'down' ? 'text-emerald-400' : 'text-amber-400'
                        }`}>
                          {card.trend === 'up' ? '↑ Increasing' :
                            card.trend === 'down' ? '↓ Decreasing' : '→ Stable'}
                        </span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </Card>

          {/* Recent Scan Activity */}
          <Card
            title="Recent Scan Activity"
            subtitle="Latest security scan results"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <RecentScans />
            </div>
          </Card>

          {/* Recent High-Risk Findings */}
          <Card
            title="Recent High-Risk Findings"
            subtitle="Critical vulnerabilities requiring attention"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <RecentRisks limit={5} />
            </div>
          </Card>

          {/* Subdomain Scan History */}
          <Card
            title="Subdomain Scan History"
            subtitle="View your previous subdomain discoveries"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <SubdomainScanHistory />
            </div>
          </Card>

          {/* Subdomain Enumeration */}
          <Card
            title="Subdomain Enumeration"
            subtitle="Discover all associated subdomains"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <SubdomainEnumerationPanel />
            </div>
          </Card>

          {/* Security Report Generator */}
          <Card
            title="Security Report Generator"
            subtitle="Export comprehensive assessments"
            className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/30 h-80 flex flex-col"
          >
            <div className="flex-1 overflow-y-auto">
              <UnifiedReportExporter />
            </div>
          </Card>
        </div>

        {/* Footer Note */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="text-center py-8 text-slate-500 text-sm"
        >
          <p>Last updated: Today at {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • Auto-refresh in 30 seconds</p>
          <p className="mt-2">Need help? Contact <a href="#" className="text-blue-400 hover:text-blue-300 transition-colors">security-support@vigilant.com</a></p>
        </motion.div>
      </div>
    </main>
  );
}