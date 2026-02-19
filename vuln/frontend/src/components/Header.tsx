import { motion } from "framer-motion";
import { 
  Shield, 
  Zap, 
  TrendingUp, 
  Cpu, 
  Sparkles,
  Target,
  BarChart3,
  AlertTriangle,
  CheckCircle,
  Clock,
  User,  // Changed from Users (not available)
  Globe,
  Server
} from "lucide-react";

interface Props {
  accuracy?: number;
  scanCount?: number;
  threatsBlocked?: number;
  uptime?: number;
}

export function Header({ 
  accuracy = 96.25, 
  scanCount = 1428,
  threatsBlocked = 247,
  uptime = 99.8
}: Props) {
  const formattedAccuracy = accuracy ? `${accuracy.toFixed(2)}%` : "96.25%";

  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-700/50 shadow-2xl"
    >
      {/* Animated background elements */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full -translate-y-32 translate-x-32" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-500/5 rounded-full -translate-x-48 translate-y-48" />
      
      <div className="relative z-10 p-8">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
          <div className="flex-1">
            {/* Team badge */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/20 rounded-full mb-6"
            >
              <User className="w-4 h-4 text-blue-400" />
              <span className="text-sm font-medium text-blue-400">Team 15 · CIC</span>
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-sm text-slate-400">Live</span>
            </motion.div>

            {/* Main title */}
            <motion.h1 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="text-4xl lg:text-5xl font-bold mb-4"
            >
              <span className="bg-gradient-to-r from-blue-400 via-cyan-300 to-purple-400 bg-clip-text text-transparent">
                Vigilant Canary
              </span>
              <br />
              <span className="text-white">Production-Grade Web Vulnerability Scanner</span>
            </motion.h1>

            {/* Subtitle */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="text-lg text-slate-300 mb-8 max-w-3xl"
            >
              Advanced hybrid Isolation Forest + LightGBM security scanner uncovering zero-day web 
              vulnerabilities before attackers can exploit them. Powered by AI-driven threat intelligence.
            </motion.p>

            {/* Stats Grid */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl"
            >
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-2">
                  <Target className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs text-slate-400">Accuracy</span>
                </div>
                <div className="text-2xl font-bold text-white">{formattedAccuracy}</div>
              </div>
              
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-2">
                  <BarChart3 className="w-4 h-4 text-blue-400" />
                  <span className="text-xs text-slate-400">Scans Completed</span>
                </div>
                <div className="text-2xl font-bold text-white">{scanCount.toLocaleString()}</div>
              </div>
              
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs text-slate-400">Threats Blocked</span>
                </div>
                <div className="text-2xl font-bold text-white">{threatsBlocked.toLocaleString()}</div>
              </div>
              
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-2">
                  <Server className="w-4 h-4 text-purple-400" />
                  <span className="text-xs text-slate-400">System Uptime</span>
                </div>
                <div className="text-2xl font-bold text-white">{uptime}%</div>
              </div>
            </motion.div>
          </div>

          {/* Main Accuracy Badge */}
          <motion.div
            initial={{ scale: 0, rotate: -180 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{ 
              type: "spring",
              stiffness: 200,
              damping: 15,
              delay: 0.6 
            }}
            className="relative"
          >
            <div className="relative">
              <div className="w-48 h-48 rounded-full bg-gradient-to-br from-blue-500/20 via-cyan-500/20 to-purple-500/20 border border-slate-700/50 backdrop-blur-sm p-8">
                <div className="absolute inset-0 rounded-full border-2 border-blue-500/30 animate-ping" style={{ animationDelay: '1s' }} />
                <div className="absolute inset-0 rounded-full border-2 border-cyan-500/30 animate-ping" style={{ animationDelay: '2s' }} />
                
                <div className="w-full h-full rounded-full bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border border-slate-700/50 flex flex-col items-center justify-center">
                  <div className="text-center">
                    <div className="text-5xl font-bold text-white mb-2">{formattedAccuracy}</div>
                    <div className="text-sm text-cyan-400 font-semibold uppercase tracking-wider">Accuracy Rate</div>
                    <div className="flex items-center justify-center gap-2 mt-3">
                      <TrendingUp className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs text-emerald-400">+2.4% from last week</span>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Corner badges */}
              <div className="absolute -top-2 -left-2 bg-gradient-to-br from-emerald-500 to-green-500 text-white text-xs font-bold px-3 py-1.5 rounded-full">
                <CheckCircle className="w-3 h-3 inline mr-1" />
                AI-Powered
              </div>
              <div className="absolute -bottom-2 -right-2 bg-gradient-to-br from-purple-500 to-pink-500 text-white text-xs font-bold px-3 py-1.5 rounded-full">
                <Sparkles className="w-3 h-3 inline mr-1" />
                Real-time
              </div>
            </div>
          </motion.div>
        </div>

        {/* Tech Stack Badges */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="flex flex-wrap items-center gap-3 mt-8 pt-8 border-t border-slate-700/50"
        >
          <span className="text-sm text-slate-400">Powered by:</span>
          <div className="flex flex-wrap gap-2">
            {[
              { label: "Isolation Forest", icon: <Cpu className="w-4 h-4" />, color: "from-blue-500/20 to-blue-500/10" },
              { label: "LightGBM", icon: <Zap className="w-4 h-4" />, color: "from-amber-500/20 to-amber-500/10" },
              { label: "AI Detection", icon: <Sparkles className="w-4 h-4" />, color: "from-purple-500/20 to-purple-500/10" },
              { label: "Zero-Day", icon: <AlertTriangle className="w-4 h-4" />, color: "from-red-500/20 to-red-500/10" },
              { label: "Global CDN", icon: <Globe className="w-4 h-4" />, color: "from-cyan-500/20 to-cyan-500/10" },
            ].map((tech, index) => (
              <motion.span
                key={tech.label}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.7 + index * 0.1 }}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium backdrop-blur-sm border border-slate-700/50 bg-gradient-to-br ${tech.color}`}
              >
                <span className="flex items-center gap-2">
                  {tech.icon}
                  <span className="text-slate-200">{tech.label}</span>
                </span>
              </motion.span>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.header>
  );
}