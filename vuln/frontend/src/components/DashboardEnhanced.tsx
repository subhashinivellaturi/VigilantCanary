import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  ChevronRight,
  Globe,
  TrendingUp,
} from 'lucide-react';
import '../styles/dashboard-enhanced.css';

interface RiskCard {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'accepted' | 'closed';
  label: string;
  count: number;
  color: string;
}

interface Scan {
  id: string;
  name: string;
  url: string;
  scanTime: Date;
  risks: number;
  status: 'completed' | 'in-progress' | 'queued';
}

interface Risk {
  id: string;
  type: string;
  port: number;
  severity: string;
}

interface Domain {
  id: string;
  domain: string;
  source: string;
  discoveredFrom: string;
}


export function DashboardEnhanced() {
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [riskCards, setRiskCards] = useState<RiskCard[]>([
    { severity: 'critical', label: 'Critical', count: 0, color: '#d946ef' },
    { severity: 'high', label: 'High', count: 0, color: '#ef4444' },
    { severity: 'medium', label: 'Medium', count: 0, color: '#f97316' },
    { severity: 'low', label: 'Low', count: 0, color: '#eab308' },
    { severity: 'accepted', label: 'Accepted', count: 0, color: '#22c55e' },
    { severity: 'closed', label: 'Closed', count: 0, color: '#9ca3af' },
  ]);
  const [recentRisks, setRecentRisks] = useState<Risk[]>([]);
  const [discoveredDomains, setDiscoveredDomains] = useState<Domain[]>([]);
  const [inProgressScans, setInProgressScans] = useState(0);
  const [scheduledScans, setScheduledScans] = useState(0);

  // Load scan history and update risk counts
  useEffect(() => {
    const loadScanHistory = () => {
      try {
        const scanHistory = localStorage.getItem('scanHistory');
        if (scanHistory) {
          const scans = JSON.parse(scanHistory) as any[];
          
          // Calculate risk counts from scan severity
          const riskCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            accepted: 0,
            closed: 0,
          };
          
          scans.forEach(scan => {
            if (scan.severity && riskCounts.hasOwnProperty(scan.severity)) {
              riskCounts[scan.severity as keyof typeof riskCounts] += 1;
            }
          });
          
          // Update risk cards with calculated counts
          setRiskCards([
            { severity: 'critical', label: 'Critical', count: riskCounts.critical, color: '#d946ef' },
            { severity: 'high', label: 'High', count: riskCounts.high, color: '#ef4444' },
            { severity: 'medium', label: 'Medium', count: riskCounts.medium, color: '#f97316' },
            { severity: 'low', label: 'Low', count: riskCounts.low, color: '#eab308' },
            { severity: 'accepted', label: 'Accepted', count: riskCounts.accepted, color: '#22c55e' },
            { severity: 'closed', label: 'Closed', count: riskCounts.closed, color: '#9ca3af' },
          ]);
          
          // Update recent scans (last 5)
          const recentData = scans.slice(0, 5).map(scan => ({
            id: scan.id,
            name: scan.target || 'Unknown',
            url: scan.target || 'N/A',
            scanTime: new Date(scan.timestamp),
            risks: scan.findings || 0,
            status: (scan.status || 'completed') as 'completed' | 'in-progress' | 'queued',
          }));
          setRecentScans(recentData);
          
          // Update recent risks
          const risksData = scans
            .filter((s: any) => s.isVulnerable)
            .slice(0, 5)
            .map((scan, idx) => ({
              id: `risk-${idx}`,
              type: scan.vulnerabilityType || 'Unknown',
              port: scan.anomalyScore || 0,
              severity: scan.severity || 'low',
            }));
          setRecentRisks(risksData);
          
          // Update discovered domains (from subdomain scans)
          const domainsData = scans
            .filter((s: any) => s.scanType === 'subdomain')
            .slice(0, 5)
            .map((scan, idx) => ({
              id: `domain-${idx}`,
              domain: scan.target || 'Unknown',
              source: scan.scanType || 'Scan',
              discoveredFrom: scan.timestamp ? new Date(scan.timestamp).toLocaleDateString() : 'Recently',
            }));
          setDiscoveredDomains(domainsData);
        }
      } catch (e) {
        console.warn('Failed to load scan history from localStorage', e);
      }
    };
    
    loadScanHistory();
    
    // Listen for new scan completions
    const handleScanCompleted = () => {
      loadScanHistory();
    };
    
    window.addEventListener('scanCompleted', handleScanCompleted);
    
    return () => {
      window.removeEventListener('scanCompleted', handleScanCompleted);
    };
  }, []);

  return (
    <div className="dashboard-enhanced">
      {/* TOP STATUS BAR */}
      <div className="dashboard-header">
        <div className="dashboard-title">
          <h1>Dashboard</h1>
        </div>
        <div className="dashboard-stats">
          <div className="stat-badge">
            <Activity size={16} />
            <span>{inProgressScans} scans in progress</span>
          </div>
          <div className="stat-badge">
            <Clock size={16} />
            <span>{scheduledScans} scheduled scans</span>
          </div>
        </div>
      </div>

      {/* RISKS DETECTED SECTION */}
      <div className="risks-section">
        <h2 className="section-title">Risk Summary</h2>
        <div className="risks-grid">
          {riskCards.slice(0, 4).map((card) => (
            <div
              key={card.severity}
              className="risk-card-minimal"
              data-severity={card.severity}
            >
              <div className="risk-card-label">{card.label}</div>
              <div className="risk-card-count">{card.count}</div>
            </div>
          ))}
        </div>
      </div>

      {/* MAIN CONTENT GRID */}
      <div className="dashboard-grid">
        {/* RECENT SCANS */}
        <div className="dashboard-section">
          <div className="section-header">
            <h3>Recent Scans</h3>
            <a href="/recent-scans" className="see-all-link">
              See all scans <ChevronRight size={14} />
            </a>
          </div>
          {recentScans.length > 0 ? (
            <div className="scans-list">
              {recentScans.map((scan) => (
                <div key={scan.id} className="scan-item">
                  <div className="scan-info">
                    <div className="scan-name">{scan.name}</div>
                    <div className="scan-url">{scan.url}</div>
                    <div className="scan-time">{scan.scanTime.toLocaleString()}</div>
                  </div>
                  <div className="scan-meta">
                    {scan.status === 'in-progress' && (
                      <span className="status-badge status-progress">
                        <span className="spinner" />
                        In Progress
                      </span>
                    )}
                    {scan.status === 'queued' && (
                      <span className="status-badge status-queued">
                        <Clock size={12} />
                        Queued
                      </span>
                    )}
                    {scan.status === 'completed' && (
                      <span className="status-badge status-complete">
                        <CheckCircle size={12} />
                        Complete
                      </span>
                    )}
                  </div>
                  {scan.status === 'completed' && (
                    <div className="scan-report">
                      <a href="#report" className="link-report">📋 Report</a>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Clock size={40} />
              <p>No scans yet. Start a new scan to see results here.</p>
            </div>
          )}
        </div>

        {/* RECENT RISKS */}
        <div className="dashboard-section">
          <div className="section-header">
            <h3>Recent Risks</h3>
            <a href="/risks" className="see-all-link">
              See all risks <ChevronRight size={14} />
            </a>
          </div>
          {recentRisks.length > 0 ? (
            <div className="risks-list">
              {recentRisks.map((risk) => (
                <div key={risk.id} className="risk-item">
                  <div className="risk-item-icon" style={{background: `${getSeverityColor(risk.severity)}20`}}>
                    <AlertTriangle size={16} color={getSeverityColor(risk.severity)} />
                  </div>
                  <div className="risk-item-info">
                    <div className="risk-item-type">{risk.type}</div>
                    <div className="risk-item-detail">Open TCP Port: {risk.port}</div>
                  </div>
                  <div className="risk-item-severity" style={{color: getSeverityColor(risk.severity)}}>
                    {risk.severity}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <AlertTriangle size={40} />
              <p>No risks detected. Run a scan to identify vulnerabilities.</p>
            </div>
          )}
        </div>

        {/* DISCOVERED DOMAINS */}
        <div className="dashboard-section">
          <div className="section-header">
            <h3>Discovered Domains</h3>
            <span className="domain-count">{discoveredDomains.length}</span>
            <a href="/subdomains" className="see-all-link">
              See all targets <ChevronRight size={14} />
            </a>
          </div>
          {discoveredDomains.length > 0 ? (
            <div className="domains-list">
              {discoveredDomains.slice(0, 5).map((domain) => (
                <div key={domain.id} className="domain-item">
                  <div className="domain-icon">
                    <Globe size={16} />
                  </div>
                  <div className="domain-info">
                    <div className="domain-name">{domain.domain}</div>
                    <div className="domain-via">via {domain.discoveredFrom}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Globe size={40} />
              <p>No domains discovered yet. Run subdomain enumeration.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '#d946ef';
    case 'high':
      return '#ef4444';
    case 'medium':
      return '#f97316';
    case 'low':
      return '#eab308';
    default:
      return '#6b7280';
  }
}

export default DashboardEnhanced;