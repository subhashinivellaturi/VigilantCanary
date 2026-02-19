import { motion, AnimatePresence } from "framer-motion";
import { 
  TrendingUp, 
  Zap, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Code, 
  FileText, 
  ExternalLink,
  Sparkles,
  Target,
  BarChart3,
  // Lightbulb,  // Not in lucide-react
  Lock,
  // Wrench,  // Not in lucide-react
  BookOpen,
  ChevronRight,
  Copy,
  Eye
} from "lucide-react";
import type { ScanResponse } from "../types";

interface Props {
  result: ScanResponse | null;
}

export function InsightGrid({ result }: Props) {
  if (!result) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl p-8 text-center"
      >
        <div className="w-16 h-16 bg-slate-800/50 border border-slate-700/50 rounded-full flex items-center justify-center mx-auto mb-4">
          {/* <Lightbulb className="w-8 h-8 text-slate-400" /> */}
        </div>
        <h3 className="text-xl font-bold text-white mb-2">No Scan Results</h3>
        <p className="text-slate-400">Run a security scan to see insights and recommendations</p>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="grid grid-cols-1 lg:grid-cols-2 gap-6"
    >
      {/* Top Signals Panel */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl overflow-hidden backdrop-blur-sm"
      >
        {/* Panel Header */}
        <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border-b border-slate-700/50 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-lg border border-blue-500/30">
              <BarChart3 className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Top Security Signals</h3>
              <p className="text-slate-400 text-sm">Feature contributions to risk score</p>
            </div>
          </div>
        </div>

        {/* Signals List */}
        <div className="p-6 space-y-4">
          <AnimatePresence>
            {result.feature_insights.map((insight, index) => {
              const contributionPercentage = (insight.contribution * 100).toFixed(1);
              const normalizedContribution = Math.min(100, Math.max(0, insight.contribution * 100));
              
              return (
                <motion.div
                  key={insight.feature}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="group relative bg-slate-800/30 border border-slate-700/40 hover:border-slate-600/60 rounded-xl p-4 transition-all duration-300 cursor-pointer hover:shadow-lg"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${
                        insight.contribution > 0.8 ? 'bg-red-500/20 border border-red-500/30' :
                        insight.contribution > 0.6 ? 'bg-orange-500/20 border border-orange-500/30' :
                        insight.contribution > 0.4 ? 'bg-yellow-500/20 border border-yellow-500/30' :
                        'bg-blue-500/20 border border-blue-500/30'
                      }`}>
                        <TrendingUp className={`w-4 h-4 ${
                          insight.contribution > 0.8 ? 'text-red-400' :
                          insight.contribution > 0.6 ? 'text-orange-400' :
                          insight.contribution > 0.4 ? 'text-yellow-400' :
                          'text-blue-400'
                        }`} />
                      </div>
                      <div>
                        <h4 className="font-semibold text-white group-hover:text-cyan-300 transition-colors">
                          {insight.feature.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </h4>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-xl font-bold ${
                        insight.contribution > 0.8 ? 'text-red-400' :
                        insight.contribution > 0.6 ? 'text-orange-400' :
                        insight.contribution > 0.4 ? 'text-yellow-400' :
                        'text-blue-400'
                      }`}>
                        {contributionPercentage}%
                      </div>
                      <div className="text-xs text-slate-400">Contribution</div>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${normalizedContribution}%` }}
                      transition={{ delay: 0.2 + index * 0.05, duration: 0.8 }}
                      className={`h-full rounded-full ${
                        insight.contribution > 0.8 ? 'bg-gradient-to-r from-red-500 to-rose-500' :
                        insight.contribution > 0.6 ? 'bg-gradient-to-r from-orange-500 to-amber-500' :
                        insight.contribution > 0.4 ? 'bg-gradient-to-r from-yellow-500 to-amber-400' :
                        'bg-gradient-to-r from-blue-500 to-cyan-500'
                      }`}
                    />
                  </div>

                  {/* Hover effect */}
                  <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-xl" />
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>

        {/* Panel Footer */}
        <div className="border-t border-slate-700/50 px-6 py-4 bg-slate-900/30">
          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-400">Total features analyzed: {result.feature_insights.length}</span>
            <button className="text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
              View all metrics <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </motion.div>

      {/* Fix Playbook Panel */}
      <motion.div
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-gradient-to-br from-slate-900/50 to-slate-950/50 border border-slate-700/50 rounded-2xl overflow-hidden backdrop-blur-sm"
      >
        {/* Panel Header */}
        <div className="bg-gradient-to-r from-emerald-500/10 to-green-500/10 border-b border-slate-700/50 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-emerald-500/20 to-green-500/20 rounded-lg border border-emerald-500/30">
              {/* <Wrench className="w-5 h-5 text-emerald-400" /> */}
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Security Playbook</h3>
              <p className="text-slate-400 text-sm">Recommended fixes & best practices</p>
            </div>
          </div>
        </div>

        {/* Suggestions List */}
        <div className="p-6 space-y-4 max-h-[500px] overflow-y-auto">
          <AnimatePresence>
            {result.suggestions.map((suggestion, index) => (
              <motion.div
                key={suggestion.title}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 + index * 0.05 }}
                className="group relative bg-gradient-to-br from-slate-800/30 to-slate-900/20 border border-slate-700/40 hover:border-emerald-500/40 rounded-xl p-5 transition-all duration-300 hover:shadow-lg"
              >
                {/* Left indicator bar */}
                <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-emerald-500 to-green-500 rounded-l-xl" />

                <div className="pl-4">
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="p-1.5 bg-emerald-500/20 rounded">
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        </div>
                        <h4 className="font-bold text-white group-hover:text-emerald-300 transition-colors">
                          {suggestion.title}
                        </h4>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {suggestion.description}
                      </p>
                    </div>
                    <button className="ml-4 p-2 hover:bg-slate-800/50 rounded-lg transition-colors">
                      <Eye className="w-4 h-4 text-slate-400" />
                    </button>
                  </div>

                  {/* Reference */}
                  {suggestion.reference && (
                    <div className="flex items-center gap-2 mt-4 pt-4 border-t border-slate-700/50">
                      <BookOpen className="w-4 h-4 text-slate-400" />
                      <span className="text-xs text-slate-400 flex-1">{suggestion.reference}</span>
                      <button className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                        Details <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex items-center gap-2 mt-4">
                    <button className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 text-xs rounded-lg transition-colors border border-emerald-500/30 flex items-center gap-1.5">
                      <Code className="w-3 h-3" />
                      View Code
                    </button>
                    <button className="px-3 py-1.5 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 text-xs rounded-lg transition-colors border border-blue-500/30 flex items-center gap-1.5">
                      <Copy className="w-3 h-3" />
                      Copy Fix
                    </button>
                  </div>
                </div>

                {/* Hover effect */}
                <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-xl" />
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {/* Panel Footer */}
        <div className="border-t border-slate-700/50 px-6 py-4 bg-slate-900/30">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-blue-500/20 rounded">
                <Sparkles className="w-4 h-4 text-blue-400" />
              </div>
              <span className="text-sm text-slate-400">AI-generated recommendations</span>
            </div>
            <button className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-700 hover:to-green-700 text-white text-sm rounded-lg font-medium transition-all shadow-lg shadow-emerald-500/20 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Apply All Fixes
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}