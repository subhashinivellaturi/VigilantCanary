import React, { useState, lazy, Suspense } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Wifi, 
  AlertCircle, 
  Loader2, 
  Server, 
  CheckCircle, 
  Zap,
  // Network,  // Not in lucide-react
  Shield,
  Target,
  Clock,
  Search,
  Filter,
  Download,
  Copy,
  Eye,
  // EyeOff,  // Not in lucide-react
  // Scan,  // Not in lucide-react
  Activity,
  BarChart3,
  RefreshCw,
  ChevronDown
} from "lucide-react";
import { SecurityCard } from './design';
import { StatusCard } from './design';
import { Button } from './ui/Button';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { useToast } from './ui/Toast';
// Chatbot is now provided globally in the sidebar
import { API_URL } from "../api/client";
import './PortScanner.css';

interface PortResult {
  port: number;
  service: string;
  state: 'open' | 'closed' | 'filtered';
  protocol: 'tcp' | 'udp';
  banner?: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
}

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  ports: string;
  timeout: number;
  threads: number;
  icon: JSX.Element;
  color: string;
}

export function PortScanner() {
  const [targetHost, setTargetHost] = useState("");
  const [portScanLoading, setPortScanLoading] = useState(false);
  const [portScanResult, setPortScanResult] = useState<any>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeProfile, setActiveProfile] = useState<string>("common");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [portRange, setPortRange] = useState("1-1000");
  const [timeout, setTimeoutValue] = useState(5);
  const [threads, setThreads] = useState(10);
  const [showBanners, setShowBanners] = useState(false);
  const { showToast } = useToast();

  const scanProfiles: ScanProfile[] = [
    { 
      id: "common", 
      name: "Common Ports", 
      description: "Quick scan of most used ports (HTTP, SSH, etc.)",
      ports: "21,22,80,443,3306,8080",
      timeout: 3,
      threads: 5,
      icon: <Zap className="h-4 w-4" />,
      color: "#10b981"
    },
    { 
      id: "standard", 
      name: "Standard Scan", 
      description: "Full scan of first 1000 ports",
      ports: "1-1000",
      timeout: 5,
      threads: 10,
      icon: <Target className="h-4 w-4" />,
      color: "#3b82f6"
    },
    { 
      id: "aggressive", 
      name: "Aggressive", 
      description: "Comprehensive scan with service detection",
      ports: "1-65535",
      timeout: 10,
      threads: 20,
      icon: <Activity className="h-4 w-4" />,
      color: "#ef4444"
    },
    { 
      id: "custom", 
      name: "Custom", 
      description: "Define your own port range",
      ports: "Custom",
      timeout: 5,
      threads: 10,
      icon: <Filter className="h-4 w-4" />,
      color: "#8b5cf6"
    }
  ];

  const commonPorts = [
    { port: 22, service: "SSH", risk: "medium", description: "Secure Shell" },
    { port: 80, service: "HTTP", risk: "low", description: "Web Server" },
    { port: 443, service: "HTTPS", risk: "low", description: "Secure Web Server" },
    { port: 3306, service: "MySQL", risk: "high", description: "Database" },
    { port: 3389, service: "RDP", risk: "critical", description: "Remote Desktop" },
    { port: 8080, service: "HTTP-ALT", risk: "medium", description: "Alternative HTTP" },
  ];

  const simulateScanProgress = () => {
    setScanProgress(0);
    const interval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + Math.random() * 10;
      });
    }, 200);
    return interval;
  };

  const handlePortScan = async () => {
    if (!targetHost.trim()) {
      showToast('Please enter a target host', 'error');
      return;
    }

    setPortScanLoading(true);
    setScanProgress(0);
    setPortScanResult(null);
    const progressInterval = simulateScanProgress();

    try {
      const profile = scanProfiles.find(p => p.id === activeProfile);
      const scanConfig = {
        target: targetHost,
        ports: activeProfile === "custom" ? portRange : profile?.ports,
        timeout: activeProfile === "custom" ? timeout : profile?.timeout,
        threads: activeProfile === "custom" ? threads : profile?.threads,
        profile: activeProfile
      };

      const response = await fetch(`${API_URL}/scan-ports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanConfig),
      });

      if (!response.ok) {
        throw new Error(`Port scan failed: ${response.statusText}`);
      }

      const data = await response.json();
      setPortScanResult(data);
      showToast('Port scan completed successfully!', 'success');
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Port scan failed";
      showToast(msg, 'error');
      
      // Simulate error result for demo
      setPortScanResult({
        target: targetHost,
        timestamp: new Date().toISOString(),
        status: "error",
        open_count: 0,
        total_scanned: 0,
        scan_time: "0s"
      });
    } finally {
      clearInterval(progressInterval);
      setScanProgress(100);
      setTimeout(() => {
        setPortScanLoading(false);
        setScanProgress(0);
      }, 500);
          window.dispatchEvent(new Event('scanCompleted'));
    }
  };

  const handlePortScanKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !portScanLoading) {
      handlePortScan();
    }
  };

  const copyResults = () => {
    navigator.clipboard.writeText(JSON.stringify(portScanResult, null, 2));
    showToast('Results copied to clipboard', 'success');
  };

  const exportResults = async () => {
    if (!portScanResult) return;
    const { jsPDF } = await import('jspdf');
    const pdf = new jsPDF();
    const margin = 20;
    let yPosition = margin;
    pdf.setFontSize(16);
    pdf.text('Port Scan Report', margin, yPosition);
    yPosition += 10;
    pdf.setFontSize(12);
    pdf.text(`Target Host: ${targetHost}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Scan Time: ${portScanResult.scan_time || 'N/A'}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Status: ${portScanResult.status || 'N/A'}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Total Ports Scanned: ${portScanResult.total_scanned || 0}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Open Ports: ${portScanResult.open_count || 0}`, margin, yPosition);
    yPosition += 10;
    pdf.setFontSize(14);
    pdf.text('Open Ports List:', margin, yPosition);
    yPosition += 8;
    pdf.setFontSize(10);
    if (portScanResult.open_ports && portScanResult.open_ports.length > 0) {
      portScanResult.open_ports.forEach((port: any, idx: number) => {
        pdf.text(`- ${port.port}/${port.protocol} (${port.service || 'Unknown'})`, margin + 5, yPosition);
        yPosition += 6;
        if (yPosition > pdf.internal.pageSize.getHeight() - margin) {
          pdf.addPage();
          yPosition = margin;
        }
      });
    } else {
      pdf.text('No open ports found.', margin + 5, yPosition);
    }
    pdf.save(`port-scan-${targetHost}-${Date.now()}.pdf`);
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#f59e0b';
      case 'low': return '#10b981';
      default: return '#6b7280';
    }
  };

  return (
    <div className="port-scanner-container">
      {/* Header Section */}
      <motion.div 
        className="scanner-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="header-content">
          <div className="header-icon">
            {/* <Network className="header-icon-svg" /> */}
          </div>
          <div>
            <h1 className="header-title">Port Scanner</h1>
            <p className="header-subtitle">Discover open ports, services, and security risks on target systems</p>
          </div>
        </div>
        <div className="header-actions">
          <Button variant="primary">
            <RefreshCw size={16} />
            History
          </Button>
          <Button variant="primary">
            <BarChart3 size={16} />
            Analytics
          </Button>
        </div>
      </motion.div>

      {/* Main Scanner Card */}
      <SecurityCard 
        title="Port Scanner Configuration" 
        subtitle="Configure and execute network port scans"
        className="scanner-config-card"
      >
        <div className="scanner-grid">
          {/* Left Panel - Target & Profiles */}
          <div className="scanner-left-panel">
            {/* Target Input */}
            <div className="target-input-group">
              <div className="input-header">
                <Search size={18} />
                <span>Target Host</span>
                <div className="input-badge">
                  <Server size={14} />
                  Network Target
                </div>
              </div>
              <div className="relative group">
                <input
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  onKeyPress={handlePortScanKeyPress}
                  placeholder="192.168.1.1 or example.com"
                  className="target-input"
                  disabled={portScanLoading}
                />
                <div className="input-gradient" />
              </div>
              <p className="input-hint">
                Enter an IP address or hostname to scan for open ports. Supports both IPv4 and domain names.
              </p>
            </div>

            {/* Scan Profiles */}
            <div className="profiles-section">
              <div className="section-header">
                <Shield size={18} />
                <span>Scan Profiles</span>
              </div>
              <div className="profiles-grid">
                {scanProfiles.map((profile) => (
                  <motion.div
                    key={profile.id}
                    className={`profile-card ${activeProfile === profile.id ? 'active' : ''}`}
                    onClick={() => setActiveProfile(profile.id)}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    style={{ borderColor: activeProfile === profile.id ? profile.color : 'transparent' }}
                  >
                    <div className="profile-icon" style={{ background: `${profile.color}20`, color: profile.color }}>
                      {profile.icon}
                    </div>
                    <div className="profile-content">
                      <h4 className="profile-name">{profile.name}</h4>
                      <p className="profile-description">{profile.description}</p>
                      <div className="profile-stats">
                        <span className="stat">
                          <Clock size={12} />
                          {profile.timeout}s timeout
                        </span>
                        <span className="stat">
                          <Activity size={12} />
                          {profile.threads} threads
                        </span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Common Ports Preview */}
            <div className="common-ports-section">
              <div className="section-header">
                <Target size={18} />
                <span>Common Ports</span>
              </div>
              <div className="ports-grid">
                {commonPorts.map((port) => (
                  <div 
                    key={port.port} 
                    className="port-chip"
                    style={{ 
                      background: `${getRiskColor(port.risk)}20`,
                      borderColor: getRiskColor(port.risk)
                    }}
                  >
                    <span className="port-number">:{port.port}</span>
                    <span className="port-service">{port.service}</span>
                    <div 
                      className="risk-dot"
                      style={{ background: getRiskColor(port.risk) }}
                    />
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Panel - Configuration & Actions */}
          <div className="scanner-right-panel">
            {/* Advanced Options Toggle */}
            <div className="advanced-toggle">
              <button 
                className="toggle-btn"
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                <Filter size={16} />
                <span>Advanced Options</span>
                <motion.div 
                  className="toggle-icon"
                  animate={{ rotate: showAdvanced ? 180 : 0 }}
                >
                  <ChevronDown size={16} />
                </motion.div>
              </button>
              
              <AnimatePresence>
                {showAdvanced && (
                  <motion.div 
                    className="advanced-options"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                  >
                    <div className="option-group">
                      <label>Port Range</label>
                      <input
                        type="text"
                        value={portRange}
                        onChange={(e) => setPortRange(e.target.value)}
                        placeholder="1-1000"
                        className="option-input"
                      />
                    </div>
                    <div className="option-group">
                      <label>Timeout (seconds)</label>
                      <div className="slider-container">
                        <input
                          type="range"
                          min="1"
                          max="30"
                          value={timeout}
                          onChange={(e) => setTimeoutValue(parseInt(e.target.value))}
                          className="slider"
                        />
                        <span className="slider-value">{timeout}s</span>
                      </div>
                    </div>
                    <div className="option-group">
                      <label>Threads</label>
                      <div className="slider-container">
                        <input
                          type="range"
                          min="1"
                          max="50"
                          value={threads}
                          onChange={(e) => setThreads(parseInt(e.target.value))}
                          className="slider"
                        />
                        <span className="slider-value">{threads}</span>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Scan Status Card */}
            <div className="status-card">
              <div className="status-header">
                <Activity size={20} />
                <span>Scan Status</span>
              </div>
              <div className="status-content">
                <div className="status-item">
                  <span className="status-label">Target</span>
                  <span className="status-value">{targetHost || "Not specified"}</span>
                </div>
                <div className="status-item">
                  <span className="status-label">Profile</span>
                  <span className="status-value">
                    {scanProfiles.find(p => p.id === activeProfile)?.name}
                  </span>
                </div>
                <div className="status-item">
                  <span className="status-label">Estimated Time</span>
                  <span className="status-value">
                    {activeProfile === 'aggressive' ? '2-5 min' : 
                     activeProfile === 'standard' ? '30-60s' : '10-30s'}
                  </span>
                </div>
              </div>
            </div>

            {/* Scan Button with Progress */}
            <div className="scan-action-section">
              <Button 
                onClick={handlePortScan} 
                disabled={portScanLoading || !targetHost.trim()}
                className="scan-btn"
                variant="primary"
              >
                {portScanLoading ? (
                  <>
                    <div className="scan-spinner" />
                    <span>Scanning... {Math.round(scanProgress)}%</span>
                  </>
                ) : (
                  <>
                    {/* <Scan size={20} /> */}
                    <span>Start Port Scan</span>
                  </>
                )}
              </Button>
              
              {portScanLoading && (
                <div className="progress-container">
                  <div className="progress-bar">
                    <motion.div 
                      className="progress-fill"
                      initial={{ width: "0%" }}
                      animate={{ width: `${scanProgress}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                  <div className="progress-stats">
                    <span>Scanning ports...</span>
                    <span>{Math.round(scanProgress)}%</span>
                  </div>
                </div>
              )}

              <div className="scan-hint">
                <AlertCircle size={14} />
                <span>Always ensure you have permission before scanning external hosts</span>
              </div>
            </div>
          </div>
        </div>
      </SecurityCard>

      {/* Results Section */}
      <AnimatePresence>
        {portScanResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
          >
            <SecurityCard 
              title="Port Scan Results" 
              subtitle={`Scan of ${targetHost} completed`}
              className="results-card"
            >
              {/* Results Header */}
              <div className="results-header">
                <div className="results-meta">
                  <div className="meta-item">
                    <div className="meta-label">Target</div>
                    <div className="meta-value">{portScanResult.target || targetHost}</div>
                  </div>
                  <div className="meta-item">
                    <div className="meta-label">Scan Time</div>
                    <div className="meta-value">{portScanResult.scan_time || "0s"}</div>
                  </div>
                  <div className="meta-item">
                    <div className="meta-label">Status</div>
                    <div className={`status-badge ${portScanResult.status}`}>
                      {portScanResult.status}
                    </div>
                  </div>
                </div>
                <div className="results-actions">
                  <Button variant="primary" onClick={copyResults}>
                    <Copy size={16} />
                    Copy
                  </Button>
                  <Button variant="primary" onClick={exportResults}>
                    <Download size={16} />
                    Export PDF
                  </Button>
                  <Button 
                    variant="primary" 
                    onClick={() => setShowBanners(!showBanners)}
                  >
                    {showBanners ? <Eye size={16} /> : <Eye size={16} />}
                    {showBanners ? 'Hide Banners' : 'Show Banners'}
                  </Button>
                </div>
              </div>

              {/* Results Summary */}
              <div className="results-summary">
                <div className="summary-card critical">
                  <div className="summary-value">{portScanResult.open_count || 0}</div>
                  <div className="summary-label">Open Ports</div>
                </div>
                <div className="summary-card high">
                  <div className="summary-value">
                    {portScanResult.high_risk_count || Math.floor((portScanResult.open_count || 0) * 0.2)}
                  </div>
                  <div className="summary-label">High Risk</div>
                </div>
                <div className="summary-card medium">
                  <div className="summary-value">{portScanResult.total_scanned || 0}</div>
                  <div className="summary-label">Total Scanned</div>
                </div>
                <div className="summary-card low">
                  <div className="summary-value">
                    {Math.round((portScanResult.open_count || 0) / (portScanResult.total_scanned || 1) * 100)}%
                  </div>
                  <div className="summary-label">Open Rate</div>
                </div>
              </div>

              {/* Ports Grid */}
              {portScanResult.open_ports && portScanResult.open_ports.length > 0 ? (
                <div className="ports-grid-results">
                  <div className="ports-header">
                    <h4>Open Ports ({portScanResult.open_ports.length})</h4>
                    <div className="ports-filter">
                      <span className="filter-label">Filter by:</span>
                      <select className="filter-select">
                        <option>All Ports</option>
                        <option>High Risk</option>
                        <option>Web Services</option>
                        <option>Database</option>
                      </select>
                    </div>
                  </div>
                  <div className="ports-table">
                    {portScanResult.open_ports.map((port: any, index: number) => (
                      <motion.div
                        key={index}
                        className="port-row"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.05 }}
                        whileHover={{ scale: 1.01, backgroundColor: 'rgba(255, 255, 255, 0.03)' }}
                      >
                        <div className="port-info">
                          <div className="port-number-badge">
                            <span className="port-number">:{port.port}</span>
                            <span className="port-protocol">{port.protocol || 'tcp'}</span>
                          </div>
                          <div className="port-details">
                            <div className="port-service">{port.service || 'Unknown'}</div>
                            <div className="port-description">
                              {port.description || 'No description available'}
                            </div>
                            {showBanners && port.banner && (
                              <div className="port-banner">{port.banner}</div>
                            )}
                          </div>
                        </div>
                        <div className="port-status">
                          <div 
                            className="risk-badge"
                            style={{ 
                              background: `${getRiskColor(port.risk || 'medium')}20`,
                              color: getRiskColor(port.risk || 'medium')
                            }}
                          >
                            {port.risk?.toUpperCase() || 'MEDIUM'}
                          </div>
                          <div className="state-badge open">
                            {port.state?.toUpperCase() || 'OPEN'}
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon={<Shield size={48} />}
                  title="No Open Ports Found"
                  description={`All scanned ports on ${targetHost} appear to be closed or filtered`}
                />
              )}

              {/* Security Recommendations */}
              {portScanResult.open_ports && portScanResult.open_ports.length > 0 && (
                <div className="recommendations-section">
                  <h4 className="recommendations-title">
                    <AlertCircle size={20} />
                    Security Recommendations
                  </h4>
                  <div className="recommendations-grid">
                    <div className="recommendation">
                      <div className="rec-icon critical">!</div>
                      <div>
                        <div className="rec-title">Close Unnecessary Ports</div>
                        <div className="rec-desc">Close ports that are not required for your service</div>
                      </div>
                    </div>
                    <div className="recommendation">
                      <div className="rec-icon high">⚠</div>
                      <div>
                        <div className="rec-title">Update Services</div>
                        <div className="rec-desc">Ensure all running services are up-to-date</div>
                      </div>
                    </div>
                    <div className="recommendation">
                      <div className="rec-icon medium">🔒</div>
                      <div>
                        <div className="rec-title">Configure Firewall</div>
                        <div className="rec-desc">Implement strict firewall rules</div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </SecurityCard>
          </motion.div>
        )}
      </AnimatePresence>

      {/* AI Security Assistant */}
      <SecurityCard 
        title="AI Security Assistant" 
        subtitle="Get insights and recommendations about your port scan results"
        className="ai-assistant-card"
      >
        <Suspense fallback={
          <div className="ai-loading">
            <div className="loading-spinner" />
            <span>Loading AI assistant...</span>
          </div>
        }>
            {/* Chatbot removed from here — available in global sidebar */}
        </Suspense>
      </SecurityCard>
    </div>
  );
}