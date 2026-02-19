import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  ChevronDown,
  Shield,
  Copy,
  ExternalLink,
  Filter,
  Search,
  X,
  Eye,
  Clock,
  Zap,
  FileText,
  BarChart3,
  Sparkles,
  TrendingUp,
  Hash,
  Globe,
  Code,
  ShieldCheck,
  Target,
  Maximize2,
  Minimize2,
  Download,
  BookOpen
} from "lucide-react";

interface Finding {
  finding_id: string;
  vulnerability_type: string;
  severity: string;
  cvss_score: number;
  confidence: number;
  description: string;
  affected_url?: string;
  affected_parameter?: string;
  http_method?: string;
  payload_used?: string;
  payload_result?: string;
  remediation_steps?: string[];
  owasp_reference?: string;
  is_duplicate?: boolean;
  duplicate_of?: string;
  timestamp?: string;
}

interface FindingsDisplayProps {
  findings: Finding[];
  scanMode: string;
  onExport?: (format: 'csv' | 'json') => void;
}

type FilterType = "all" | string;

const VULNERABILITY_NAMES: Record<string, string> = {
  insecure_http: "Insecure HTTP",
  missing_security_headers: "Missing Security Headers",
  open_directory: "Open Directory",
  xss: "Cross-Site Scripting (XSS)",
  sql_injection: "SQL Injection",
  csrf: "CSRF Protection",
  path_traversal: "Path Traversal",
  command_injection: "Command Injection",
};

const SEVERITY_CONFIG: Record<string, { 
  bg: string; 
  text: string; 
  border: string; 
  icon: React.ReactNode;
  gradient: string;
  badge: string;
}> = {
  critical: { 
    bg: "bg-red-500/10", 
    text: "text-red-400", 
    border: "border-red-500/30", 
    icon: <AlertCircle className="w-5 h-5 text-red-400" />,
    gradient: "from-red-600 to-rose-600",
    badge: "bg-red-500/20 text-red-400 border-red-500/30"
  },
  high: { 
    bg: "bg-orange-500/10", 
    text: "text-orange-400", 
    border: "border-orange-500/30", 
    icon: <AlertTriangle className="w-5 h-5 text-orange-400" />,
    gradient: "from-orange-500 to-amber-500",
    badge: "bg-orange-500/20 text-orange-400 border-orange-500/30"
  },
  medium: { 
    bg: "bg-yellow-500/10", 
    text: "text-yellow-400", 
    border: "border-yellow-500/30", 
    icon: <AlertTriangle className="w-5 h-5 text-yellow-400" />,
    gradient: "from-yellow-500 to-amber-400",
    badge: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
  },
  low: { 
    bg: "bg-blue-500/10", 
    text: "text-blue-400", 
    border: "border-blue-500/30", 
    icon: <Shield className="w-5 h-5 text-blue-400" />,
    gradient: "from-cyan-500 to-blue-500",
    badge: "bg-blue-500/20 text-blue-400 border-blue-500/30"
  },
};

const VULNERABILITY_COLORS: Record<string, { bg: string; text: string }> = {
  insecure_http: { bg: "bg-teal-500/20", text: "text-teal-400" },
  missing_security_headers: { bg: "bg-indigo-500/20", text: "text-indigo-400" },
  open_directory: { bg: "bg-orange-500/20", text: "text-orange-400" },
  xss: { bg: "bg-red-500/20", text: "text-red-400" },
  sql_injection: { bg: "bg-amber-500/20", text: "text-amber-400" },
  csrf: { bg: "bg-purple-500/20", text: "text-purple-400" },
  path_traversal: { bg: "bg-cyan-500/20", text: "text-cyan-400" },
  command_injection: { bg: "bg-pink-500/20", text: "text-pink-400" },
};

export function FindingsDisplay({ findings, scanMode, onExport }: FindingsDisplayProps) {
  const [filter, setFilter] = useState<FilterType>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<'list' | 'grid'>('list');

  // Get unique vulnerability types
  const vulnerabilityTypes = useMemo(() => {
    const types = new Set(findings.map((f) => f.vulnerability_type));
    return Array.from(types).sort();
  }, [findings]);

  // Get unique severities
  const severities = useMemo(() => {
    const sev = new Set(findings.map((f) => f.severity));
    return Array.from(sev).sort();
  }, [findings]);

  // Filter findings
  const filteredFindings = useMemo(() => {
    let result = findings;
    
    // Apply vulnerability type filter
    if (filter !== "all") {
      result = result.filter((f) => f.vulnerability_type === filter);
    }
    
    // Apply severity filter
    if (severityFilter !== "all") {
      result = result.filter((f) => f.severity === severityFilter);
    }
    
    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter((f) => 
        f.description.toLowerCase().includes(query) ||
        f.vulnerability_type.toLowerCase().includes(query) ||
        f.finding_id.toLowerCase().includes(query) ||
        (f.affected_url?.toLowerCase() || '').includes(query)
      );
    }
    
    return result;
  }, [findings, filter, severityFilter, searchQuery]);

  // Count findings by type
  const findingCounts = useMemo(() => {
    const counts: Record<string, number> = { all: findings.length };
    vulnerabilityTypes.forEach((type) => {
      counts[type] = findings.filter((f) => f.vulnerability_type === type).length;
    });
    return counts;
  }, [findings, vulnerabilityTypes]);

  // Count findings by severity
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { all: findings.length };
    severities.forEach((sev) => {
      counts[sev] = findings.filter((f) => f.severity === sev).length;
    });
    return counts;
  }, [findings, severities]);

  const getSeverityBadge = (severity: string) => {
    const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low;
    return config.icon;
  };

  const copyFindingId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const isScanPassive = scanMode === "passive_only";

  const formatTimestamp = (timestamp?: string) => {
    if (!timestamp) return "";
    try {
      return new Date(timestamp).toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return timestamp;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-sm"
    >
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-800/50 to-slate-900/50 px-6 py-5 border-b border-slate-700/50">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-2 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">Security Findings</h3>
              <p className="text-slate-400 text-sm mt-1">
                {isScanPassive
                  ? "🔍 Passive Security Assessment - No payloads injected"
                  : "⚡ Active Security Assessment - Payloads tested"}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 pr-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 w-48"
              />
            </div>
            
            <div className="flex gap-2">
              <button
                onClick={() => onExport?.('csv')}
                className="px-3 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-lg text-sm font-medium transition-colors border border-emerald-500/30 flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                CSV
              </button>
              <button
                onClick={() => onExport?.('json')}
                className="px-3 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg text-sm font-medium transition-colors border border-blue-500/30 flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                JSON
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="px-6 py-4 border-b border-slate-700/50 bg-gradient-to-r from-slate-900/30 to-slate-800/30">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{findings.length}</div>
            <div className="text-xs text-slate-400">Total Findings</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">
              {findings.filter(f => f.severity === 'critical').length}
            </div>
            <div className="text-xs text-slate-400">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-400">
              {findings.filter(f => f.severity === 'high').length}
            </div>
            <div className="text-xs text-slate-400">High</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-cyan-400">
              {findings.length > 0 ? 
                (findings.reduce((sum, f) => sum + f.cvss_score, 0) / findings.length).toFixed(1) : '0.0'
              }
            </div>
            <div className="text-xs text-slate-400">Avg CVSS</div>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Filters */}
        <div className="space-y-4">
          {/* Vulnerability Type Filters */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Filter className="w-4 h-4 text-slate-400" />
              <span className="text-sm text-slate-400">Filter by Vulnerability Type</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => setFilter("all")}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${filter === "all" 
                  ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" 
                  : "text-slate-400 hover:text-slate-300 hover:bg-slate-800/50 border border-slate-700/50"}`}
              >
                All Types ({findingCounts.all})
              </motion.button>
              
              {vulnerabilityTypes.map((type) => {
                const colors = VULNERABILITY_COLORS[type] || { bg: "bg-slate-500/20", text: "text-slate-400" };
                return (
                  <motion.button
                    key={type}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => setFilter(type)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${filter === type 
                      ? `${colors.bg} ${colors.text} border border-slate-700/50` 
                      : "text-slate-400 hover:text-slate-300 hover:bg-slate-800/50 border border-slate-700/50"}`}
                  >
                    {VULNERABILITY_NAMES[type] || type} ({findingCounts[type]})
                  </motion.button>
                );
              })}
            </div>
          </div>

          {/* Severity Filters */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <BarChart3 className="w-4 h-4 text-slate-400" />
              <span className="text-sm text-slate-400">Filter by Severity</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => setSeverityFilter("all")}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${severityFilter === "all" 
                  ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" 
                  : "text-slate-400 hover:text-slate-300 hover:bg-slate-800/50 border border-slate-700/50"}`}
              >
                All Severities ({severityCounts.all})
              </motion.button>
              
              {severities.map((sev) => {
                const config = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.low;
                return (
                  <motion.button
                    key={sev}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${severityFilter === sev 
                      ? `${config.bg} ${config.text} border ${config.border}` 
                      : "text-slate-400 hover:text-slate-300 hover:bg-slate-800/50 border border-slate-700/50"}`}
                  >
                    {config.icon}
                    <span className="ml-1.5 capitalize">{sev}</span>
                    <span className="ml-2 text-xs bg-black/20 px-1.5 py-0.5 rounded">
                      {severityCounts[sev]}
                    </span>
                  </motion.button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Findings List */}
        {filteredFindings.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-12 bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 rounded-xl"
          >
            <div className="w-16 h-16 bg-slate-800/50 border border-slate-700/50 rounded-full flex items-center justify-center mx-auto mb-4">
              <Search className="w-8 h-8 text-slate-400" />
            </div>
            <h4 className="text-lg font-bold text-white mb-2">No Findings Found</h4>
            <p className="text-slate-400 max-w-md mx-auto">
              {searchQuery 
                ? `No findings match your search "${searchQuery}"`
                : `No ${filter !== "all" ? VULNERABILITY_NAMES[filter] || filter : ""} ${severityFilter !== "all" ? severityFilter : ""} findings detected`
              }
            </p>
            {(searchQuery || filter !== "all" || severityFilter !== "all") && (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => {
                  setFilter("all");
                  setSeverityFilter("all");
                  setSearchQuery("");
                }}
                className="mt-4 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg text-sm font-medium transition-colors border border-blue-500/30"
              >
                Clear All Filters
              </motion.button>
            )}
          </motion.div>
        ) : (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-4"
          >
            <div className="flex items-center justify-between">
              <div className="text-sm text-slate-400">
                Showing <span className="font-bold text-white">{filteredFindings.length}</span> of {findings.length} findings
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setViewMode(viewMode === 'list' ? 'grid' : 'list')}
                  className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors"
                >
                  {viewMode === 'list' ? 
                    <Maximize2 className="w-4 h-4 text-slate-400" /> : 
                    <Minimize2 className="w-4 h-4 text-slate-400" />
                  }
                </button>
              </div>
            </div>

            <AnimatePresence>
              {filteredFindings.map((finding, index) => {
                const isExpanded = expandedFinding === finding.finding_id;
                const config = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.low;
                const vulnColors = VULNERABILITY_COLORS[finding.vulnerability_type] || { bg: "bg-slate-500/20", text: "text-slate-400" };

                return (
                  <motion.div
                    key={finding.finding_id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ delay: index * 0.05 }}
                    className={`${config.bg} ${config.border} border rounded-xl overflow-hidden group hover:shadow-lg transition-all duration-300`}
                  >
                    {/* Finding Header */}
                    <motion.button
                      onClick={() => setExpandedFinding(isExpanded ? null : finding.finding_id)}
                      className="w-full p-5 cursor-pointer text-left"
                      whileHover={{ x: 4 }}
                    >
                      <div className="flex items-start gap-4">
                        {/* Severity Icon */}
                        <div className="flex-shrink-0">
                          <div className={`p-3 rounded-lg bg-gradient-to-br ${config.gradient}`}>
                            {config.icon}
                          </div>
                        </div>

                        {/* Main Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2 mb-3">
                            <span className={`text-xs font-bold px-2.5 py-1 rounded-full uppercase ${config.badge}`}>
                              {finding.severity}
                            </span>
                            <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${vulnColors.bg} ${vulnColors.text}`}>
                              {VULNERABILITY_NAMES[finding.vulnerability_type] || finding.vulnerability_type}
                            </span>
                            {finding.is_duplicate && (
                              <span className="text-xs font-bold px-2.5 py-1 rounded-full bg-slate-500/20 text-slate-400 border border-slate-500/30">
                                Duplicate
                              </span>
                            )}
                          </div>

                          <h4 className="text-base font-semibold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                            {finding.description.substring(0, 120)}
                            {finding.description.length > 120 && "..."}
                          </h4>

                          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
                            {finding.affected_url && (
                              <div className="flex items-center gap-1.5">
                                <Globe className="w-4 h-4" />
                                <span className="truncate max-w-xs">{finding.affected_url}</span>
                              </div>
                            )}
                            {finding.timestamp && (
                              <div className="flex items-center gap-1.5">
                                <Clock className="w-4 h-4" />
                                <span>{formatTimestamp(finding.timestamp)}</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Right Side - Metrics & Chevron */}
                        <div className="flex items-center gap-4">
                          <div className="text-right">
                            <div className={`text-xl font-bold ${config.text}`}>
                              CVSS {finding.cvss_score.toFixed(1)}
                            </div>
                            <div className="text-xs text-slate-400">
                              Confidence: {Math.round(finding.confidence)}%
                            </div>
                          </div>
                          <ChevronDown
                            className={`w-5 h-5 text-slate-400 transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}
                          />
                        </div>
                      </div>
                    </motion.button>

                    {/* Expanded Details */}
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          className="border-t border-slate-700/50"
                        >
                          <div className="p-5 bg-gradient-to-br from-slate-900/50 to-slate-900/30 space-y-5">
                            {/* ID & Basic Info */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <Hash className="w-4 h-4" />
                                  Finding ID
                                </div>
                                <div className="flex items-center gap-2">
                                  <code className="text-sm text-slate-300 bg-slate-800/50 px-3 py-2 rounded-lg border border-slate-700/50 flex-1">
                                    {finding.finding_id}
                                  </code>
                                  <motion.button
                                    whileHover={{ scale: 1.1 }}
                                    whileTap={{ scale: 0.9 }}
                                    onClick={() => copyFindingId(finding.finding_id)}
                                    className={`p-2 rounded-lg ${copiedId === finding.finding_id 
                                      ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                                      : "bg-slate-800/50 text-slate-400 hover:text-white hover:bg-slate-700/50 border border-slate-700/50"}`}
                                  >
                                    {copiedId === finding.finding_id ? 
                                      <CheckCircle className="w-4 h-4" /> : 
                                      <Copy className="w-4 h-4" />
                                    }
                                  </motion.button>
                                </div>
                              </div>

                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <Target className="w-4 h-4" />
                                  Severity Metrics
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                  <div className={`${config.bg} border ${config.border} rounded-lg p-3 text-center`}>
                                    <div className={`text-2xl font-bold ${config.text}`}>
                                      {finding.cvss_score.toFixed(1)}
                                    </div>
                                    <div className="text-xs text-slate-400">CVSS Score</div>
                                  </div>
                                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-center">
                                    <div className="text-2xl font-bold text-blue-400">
                                      {Math.round(finding.confidence)}%
                                    </div>
                                    <div className="text-xs text-slate-400">Confidence</div>
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Detailed Description */}
                            <div className="space-y-2">
                              <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                <FileText className="w-4 h-4" />
                                Detailed Description
                              </div>
                              <p className="text-slate-300 bg-slate-800/30 border border-slate-700/50 rounded-lg p-4">
                                {finding.description}
                              </p>
                            </div>

                            {/* Affected Location */}
                            {(finding.affected_url || finding.affected_parameter) && (
                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <Globe className="w-4 h-4" />
                                  Affected Location
                                </div>
                                <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-4 space-y-2">
                                  {finding.affected_url && (
                                    <div className="flex items-start gap-2">
                                      <span className="text-slate-400 text-sm min-w-16">URL:</span>
                                      <code className="text-slate-300 text-sm flex-1">{finding.affected_url}</code>
                                    </div>
                                  )}
                                  {finding.affected_parameter && (
                                    <div className="flex items-start gap-2">
                                      <span className="text-slate-400 text-sm min-w-16">Parameter:</span>
                                      <code className="text-slate-300 text-sm flex-1">{finding.affected_parameter}</code>
                                    </div>
                                  )}
                                  {finding.http_method && (
                                    <div className="flex items-start gap-2">
                                      <span className="text-slate-400 text-sm min-w-16">Method:</span>
                                      <code className="text-slate-300 text-sm flex-1">{finding.http_method}</code>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Payload Section - Only if Active */}
                            {!isScanPassive && finding.payload_used && (
                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <Zap className="w-4 h-4" />
                                  Payload Tested
                                </div>
                                <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
                                  <code className="text-slate-300 text-sm whitespace-pre-wrap break-all">
                                    {finding.payload_used}
                                  </code>
                                  {finding.payload_result && (
                                    <div className="mt-3 pt-3 border-t border-slate-700/50">
                                      <div className="text-xs text-slate-400 mb-2">Result:</div>
                                      <div className="text-slate-300 text-sm">
                                        {finding.payload_result}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Remediation Steps */}
                            {finding.remediation_steps && finding.remediation_steps.length > 0 && (
                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <Sparkles className="w-4 h-4" />
                                  Remediation Steps
                                </div>
                                <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4">
                                  <ul className="space-y-2">
                                    {finding.remediation_steps.map((step, idx) => (
                                      <li key={idx} className="flex items-start gap-3">
                                        <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                                          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                                        </div>
                                        <span className="text-sm text-emerald-300 flex-1">{step}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </div>
                            )}

                            {/* OWASP Reference */}
                            {finding.owasp_reference && (
                              <div className="space-y-2">
                                <div className="flex items-center gap-2 text-xs text-slate-400 uppercase">
                                  <BookOpen className="w-4 h-4" />
                                  OWASP Reference
                                </div>
                                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                                  <div className="text-blue-400 font-medium">{finding.owasp_reference}</div>
                                </div>
                              </div>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}