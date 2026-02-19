import React from "react";
import { motion } from "framer-motion";
import {
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Shield,
  Download,
  ExternalLink,
  Clock,
  Globe,
  Zap,
  Target,
  TrendingUp,
  TrendingDown,
  FileText,
  Sparkles
} from "lucide-react";

interface ExecutiveSummary {
  scan_timestamp: string;
  scanned_url: string;
  scan_mode: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  overall_risk_status: string;
  risk_score_0_to_100: number;
  executive_summary_text: string;
  remediation_priority: string;
}

interface ExecutiveSummaryPanelProps {
  summary: ExecutiveSummary;
  onExportPDF?: () => void;
}

export function ExecutiveSummaryPanel({ summary, onExportPDF }: ExecutiveSummaryPanelProps) {
  const getRiskConfig = (status: string) => {
    switch (status.toLowerCase()) {
      case "safe":
        return {
          bg: "from-emerald-500/10 to-green-500/10",
          border: "border-emerald-500/30",
          text: "text-emerald-400",
          icon: <CheckCircle size={32} className="text-emerald-400" />,
          gradient: "from-emerald-500 to-green-500",
          badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
        };
      case "suspicious":
        return {
          bg: "from-amber-500/10 to-yellow-500/10",
          border: "border-amber-500/30",
          text: "text-amber-400",
          icon: <AlertTriangle size={32} className="text-amber-400" />,
          gradient: "from-amber-500 to-yellow-500",
          badge: "bg-amber-500/20 text-amber-400 border-amber-500/30"
        };
      case "unsafe":
        return {
          bg: "from-red-500/10 to-rose-500/10",
          border: "border-red-500/30",
          text: "text-red-400",
          icon: <AlertCircle size={32} className="text-red-400" />,
          gradient: "from-red-500 to-rose-500",
          badge: "bg-red-500/20 text-red-400 border-red-500/30"
        };
      default:
        return {
          bg: "from-blue-500/10 to-cyan-500/10",
          border: "border-blue-500/30",
          text: "text-blue-400",
          icon: <Shield size={32} className="text-blue-400" />,
          gradient: "from-blue-500 to-cyan-500",
          badge: "bg-blue-500/20 text-blue-400 border-blue-500/30"
        };
    }
  };

  const formatTimestamp = (isoString: string) => {
    try {
      return new Date(isoString).toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return isoString;
    }
  };

  const riskConfig = getRiskConfig(summary.overall_risk_status);
  
  const severityData = [
    { label: "Critical", count: summary.critical_count, color: "from-red-600 to-rose-600", bg: "bg-red-500/10", text: "text-red-400" },
    { label: "High", count: summary.high_count, color: "from-orange-500 to-amber-500", bg: "bg-orange-500/10", text: "text-orange-400" },
    { label: "Medium", count: summary.medium_count, color: "from-yellow-500 to-amber-400", bg: "bg-yellow-500/10", text: "text-yellow-400" },
    { label: "Low", count: summary.low_count, color: "from-cyan-500 to-blue-500", bg: "bg-cyan-500/10", text: "text-cyan-400" }
  ];

  const getRemediationPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case "immediate": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      case "low": return "text-blue-400 bg-blue-500/10 border-blue-500/30";
      default: return "text-slate-400 bg-slate-500/10 border-slate-500/30";
    }
  };

  const getRiskTrend = (score: number) => {
    if (score >= 80) return { text: "Excellent", color: "text-emerald-400", icon: TrendingUp };
    if (score >= 60) return { text: "Good", color: "text-green-400", icon: TrendingUp };
    if (score >= 40) return { text: "Moderate", color: "text-yellow-400", icon: TrendingUp };
    return { text: "Needs Attention", color: "text-red-400", icon: TrendingDown };
  };

  const riskTrend = getRiskTrend(summary.risk_score_0_to_100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-sm"
    >
      {/* Header with Risk Status */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className={`${riskConfig.bg} ${riskConfig.border} border-b p-6`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className={`p-4 rounded-2xl bg-gradient-to-br ${riskConfig.gradient} shadow-lg`}>
                {riskConfig.icon}
              </div>
              <div className="absolute -top-2 -right-2">
                <div className={`px-3 py-1 rounded-full text-xs font-bold ${riskConfig.badge} border`}>
                  {summary.overall_risk_status.toUpperCase()}
                </div>
              </div>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Security Assessment Summary</h1>
              <p className="text-slate-400 text-sm mt-1">Comprehensive security analysis report</p>
            </div>
          </div>
          
          {onExportPDF && (
            <motion.button
              whileHover={{ scale: 1.05, boxShadow: "0 10px 25px rgba(59, 130, 246, 0.3)" }}
              whileTap={{ scale: 0.95 }}
              onClick={onExportPDF}
              className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white rounded-xl font-semibold transition-all shadow-lg shadow-blue-500/50 flex items-center gap-2"
            >
              <Download className="w-5 h-5" />
              Export PDF Report
            </motion.button>
          )}
        </div>
      </motion.div>

      <div className="p-6 space-y-6">
        {/* Executive Summary Text */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-lg border border-purple-500/30">
              <FileText className="w-5 h-5 text-purple-400" />
            </div>
            <h2 className="text-lg font-bold text-white">Executive Summary</h2>
          </div>
          <p className="text-slate-300 leading-relaxed">
            {summary.executive_summary_text}
          </p>
        </motion.div>

        {/* Risk Score & Statistics */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="grid grid-cols-1 lg:grid-cols-3 gap-6"
        >
          {/* Risk Score Card */}
          <div className="lg:col-span-1 bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-6">
            <div className="text-center mb-6">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium mb-3">
                <Shield className="w-4 h-4" />
                Risk Score
              </div>
              <div className="relative w-32 h-32 mx-auto">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
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
                    stroke={`url(#scoreGradient)`}
                    strokeWidth="3"
                    strokeDasharray={`${summary.risk_score_0_to_100}, 100`}
                    strokeLinecap="round"
                  />
                  <defs>
                    <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" style={{ stopColor: riskTrend.color.replace('text-', ''), stopOpacity: 1 }} />
                      <stop offset="100%" style={{ stopColor: riskTrend.color.replace('text-', ''), stopOpacity: 0.8 }} />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <div className="text-3xl font-bold text-white">{summary.risk_score_0_to_100}</div>
                  <div className="text-sm text-slate-400">/100</div>
                </div>
              </div>
              <div className={`inline-flex items-center gap-1.5 mt-4 px-3 py-1.5 rounded-full text-sm font-medium ${riskTrend.color} bg-black/20`}>
                {riskTrend.icon && <riskTrend.icon className="w-4 h-4" />}
                {riskTrend.text}
              </div>
            </div>
          </div>

          {/* Findings Statistics */}
          <div className="lg:col-span-2 bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Target className="w-5 h-5 text-cyan-400" />
                Vulnerability Statistics
              </h3>
              <div className="text-sm text-slate-400">
                Total: <span className="font-bold text-white">{summary.total_findings}</span>
              </div>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {severityData.map((severity, index) => (
                <motion.div
                  key={severity.label}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.3 + index * 0.1 }}
                  whileHover={{ scale: 1.05 }}
                  className={`${severity.bg} border border-slate-700/40 rounded-xl p-4 text-center cursor-pointer hover:shadow-lg transition-all`}
                >
                  <div className={`text-3xl font-bold ${severity.text} mb-2`}>
                    {severity.count}
                  </div>
                  <div className="text-sm font-semibold text-white">{severity.label}</div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden mt-3">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.min(100, (severity.count / Math.max(1, summary.total_findings)) * 100)}%` }}
                      transition={{ delay: 0.5 + index * 0.1, duration: 1 }}
                      className={`h-full bg-gradient-to-r ${severity.color}`}
                    />
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Scan Details */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl p-6"
        >
          <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-400" />
            Scan Details
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* URL */}
            <div className="p-4 bg-slate-800/30 border border-slate-700/40 rounded-lg">
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <Globe className="w-4 h-4" />
                SCANNED URL
              </div>
              <div className="text-sm text-white font-mono truncate" title={summary.scanned_url}>
                {summary.scanned_url}
              </div>
            </div>

            {/* Scan Mode */}
            <div className="p-4 bg-slate-800/30 border border-slate-700/40 rounded-lg">
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <Zap className="w-4 h-4" />
                SCAN MODE
              </div>
              <div className="flex items-center gap-2">
                <div className={`px-2 py-1 rounded text-xs font-medium ${
                  summary.scan_mode === "passive_only" 
                    ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" 
                    : "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                }`}>
                  {summary.scan_mode === "passive_only" ? "🔍 Passive" : "⚡ Active"}
                </div>
                <div className="text-sm text-white">
                  {summary.scan_mode === "passive_only" ? "Passive Scan Only" : "Active with Payload"}
                </div>
              </div>
            </div>

            {/* Timestamp */}
            <div className="p-4 bg-slate-800/30 border border-slate-700/40 rounded-lg">
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <Clock className="w-4 h-4" />
                SCAN TIMESTAMP
              </div>
              <div className="text-sm text-white">
                {formatTimestamp(summary.scan_timestamp)}
              </div>
            </div>

            {/* Remediation Priority */}
            <div className="p-4 bg-slate-800/30 border border-slate-700/40 rounded-lg">
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <Target className="w-4 h-4" />
                REMEDIATION PRIORITY
              </div>
              <div className={`px-3 py-1.5 rounded-lg text-sm font-bold text-center ${getRemediationPriorityColor(summary.remediation_priority)} border`}>
                {summary.remediation_priority}
              </div>
            </div>
          </div>
        </motion.div>

        {/* Recommendations */}
        {summary.overall_risk_status.toLowerCase() !== "safe" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="bg-gradient-to-r from-blue-500/10 via-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-6"
          >
            <div className="flex items-start gap-4">
              <div className="p-3 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-lg border border-cyan-500/30">
                <TrendingUp className="w-6 h-6 text-cyan-400" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-bold text-white mb-3">Recommended Next Steps</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="flex items-start gap-2">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                        <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      </div>
                      <p className="text-sm text-cyan-300">Review detailed findings for specific vulnerability details</p>
                    </div>
                    <div className="flex items-start gap-2">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                        <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      </div>
                      <p className="text-sm text-cyan-300">Prioritize fixes based on severity level (Critical → High → Medium → Low)</p>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-start gap-2">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                        <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      </div>
                      <p className="text-sm text-cyan-300">Implement recommended remediation steps for each finding</p>
                    </div>
                    <div className="flex items-start gap-2">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                        <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      </div>
                      <p className="text-sm text-cyan-300">Re-scan after fixes to verify vulnerabilities have been resolved</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Footer Actions */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="flex items-center justify-between pt-6 border-t border-slate-700/50"
        >
          <div className="text-sm text-slate-400">
            Generated on {formatTimestamp(new Date().toISOString())}
          </div>
          <div className="flex items-center gap-3">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 border border-slate-700/50"
            >
              <ExternalLink className="w-4 h-4" />
              View Detailed Report
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05, boxShadow: "0 8px 20px rgba(59, 130, 246, 0.2)" }}
              whileTap={{ scale: 0.95 }}
              className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2 shadow-lg shadow-emerald-500/20"
            >
              <Shield className="w-4 h-4" />
              Schedule Rescan
            </motion.button>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}