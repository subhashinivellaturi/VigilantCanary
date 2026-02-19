import React, { useState } from 'react';
import { Wifi, Zap, X, Download, Copy, AlertTriangle, CheckCircle } from 'lucide-react';
import '../styles/PortScanner.css';

import { API_URL } from '../api/client';

interface PortResult {
  port: number;
  status: 'open' | 'closed' | 'filtered';
  service: string;
  banner?: string;
}

interface ScanProgress {
  current: number;
  total: number;
  percent: number;
}

const COMMON_PORTS: { [key: number]: string } = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  8080: 'HTTP Proxy',
  8443: 'HTTPS Alt',
  27017: 'MongoDB',
  6379: 'Redis',
};

export function PortScanner() {
  const [host, setHost] = useState('');
  const [portRange, setPortRange] = useState('1-1000');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<PortResult[]>([]);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [error, setError] = useState('');
  const [copiedPort, setCopiedPort] = useState<number | null>(null);

  const validateInput = (): boolean => {
    if (!host.trim()) {
      setError('Please enter a host IP or hostname');
      return false;
    }

    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-z0-9.-]+\.[a-z]{2,}$/i;
    if (!ipRegex.test(host.trim())) {
      setError('Please enter a valid IP address or hostname');
      return false;
    }

    return true;
  };

  const parsePortRange = (): number[] => {
    const ports: number[] = [];
    const ranges = portRange.split(',').map(r => r.trim());

    for (const range of ranges) {
      if (range.includes('-')) {
        const [start, end] = range.split('-').map(p => parseInt(p.trim()));
        if (!isNaN(start) && !isNaN(end)) {
          for (let i = start; i <= end; i++) {
            if (i >= 1 && i <= 65535) {
              ports.push(i);
            }
          }
        }
      } else {
        const port = parseInt(range);
        if (!isNaN(port) && port >= 1 && port <= 65535) {
          ports.push(port);
        }
      }
    }

    return [...new Set(ports)].sort((a, b) => a - b);
  };



  const handleScan = async () => {
    if (!validateInput()) return;
    setIsScanning(true);
    setError('');
    setResults([]);
    setProgress(null);

    try {
      const response = await fetch(`${API_URL}/port-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: host, port_range: portRange }),
      });
      if (!response.ok) throw new Error('Scan failed');
      const data = await response.json();
      if (data.status !== 'success') {
        setError(data.message || 'Scan failed');
        setResults([]);
        return;
      }
      // Map backend 'state' to frontend 'status'
      let mappedResults = (data.results || []).map((r: any) => ({
        port: r.port,
        status: r.state, // backend uses 'state', frontend expects 'status'
        service: r.service,
        banner: r.banner || '',
      }));
      // If no results, but scanned_ports is present, show all as closed
      if (mappedResults.length === 0 && Array.isArray(data.scanned_ports) && data.scanned_ports.length > 0) {
        mappedResults = data.scanned_ports.map((port: number) => ({
          port,
          status: 'closed',
          service: COMMON_PORTS[port] || '',
        }));
      }
      setResults(mappedResults);
      window.dispatchEvent(new Event('scanCompleted'));
    } catch (err) {
      setError('Scan encountered an error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleStop = () => {
    setIsScanning(false);
  };

  const handleClear = () => {
    setHost('');
    setPortRange('1-1000');
    setResults([]);
    setProgress(null);
    setError('');
  };

  const copyToClipboard = (port: number) => {
    navigator.clipboard.writeText(port.toString());
    setCopiedPort(port);
    setTimeout(() => setCopiedPort(null), 2000);
  };

  const exportResults = () => {
    const data = {
      host,
      portRange,
      scanTime: new Date().toISOString(),
      totalPorts: results.length,
      openPorts: results.filter(r => r.status === 'open').length,
      results,
    };

    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `port-scan-${host}-${Date.now()}.json`;
    a.click();
  };

  const openPorts = results.filter(r => r.status === 'open');
  const filteredPorts = results.filter(r => r.status === 'filtered');
  const closedPorts = results.filter(r => r.status === 'closed');

  return (
    <div className="port-scanner">
      <div className="scanner-header">
        <h1>Port Scanner</h1>
        <p>Scan for open ports and discover running services</p>
      </div>

      <div className="card card--glass scanner-card">
        <div className="scanner-form">
          <div className="form-group">
            <label htmlFor="host" className="input-label">
              Host / IP Address <span className="required">*</span>
            </label>
            <p className="input-hint">Enter target IP (e.g., 192.168.1.1) or hostname (e.g., example.com)</p>
            <div className="input-wrapper">
              <Wifi size={18} className="input-icon" />
              <input
                id="host"
                type="text"
                className="input"
                placeholder="192.168.1.1 or example.com"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="portRange" className="input-label">
              Port Range <span className="required">*</span>
            </label>
            <p className="input-hint">Single ports or ranges separated by commas (e.g., 1-100, 443, 8080, 3306)</p>
            <input
              id="portRange"
              type="text"
              className="input"
              placeholder="1-1000"
              value={portRange}
              onChange={(e) => setPortRange(e.target.value)}
              disabled={isScanning}
            />
          </div>

          {error && (
            <div className="alert alert--error" role="alert">
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div className="form-actions">
            {!isScanning ? (
              <button className="btn btn--primary" onClick={handleScan} disabled={isScanning}>
                <Zap size={16} />
                Start Scan
              </button>
            ) : (
              <button className="btn btn--primary" onClick={handleStop}>
                <X size={16} />
                Stop Scan
              </button>
            )}
            <button className="btn btn--ghost" onClick={handleClear} disabled={isScanning}>
              Clear
            </button>
          </div>
        </div>
      </div>

      {progress && (
        <div className="progress-section">
          <div className="progress-info">
            <span className="progress-label">Scanning in progress...</span>
            <span className="progress-counter">
              {progress.current} / {progress.total} ports ({progress.percent}%)
            </span>
          </div>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress.percent}%` }} />
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="results-section grid-layout">
          <div className="results-header flex-between">
            <div className="results-title flex-center">
              <Wifi size={24} />
              <div>
                <h2>Scan Results for {host}</h2>
              </div>
            </div>
            <button className="btn btn--secondary" onClick={exportResults}>
              <Download size={16} />
              Export JSON
            </button>
          </div>
          <div className="results-stats grid grid-cols-3 gap-4 mb-6">
            <div className="stat-card stat-open">
              <span className="stat-label">Open</span>
              <span className="stat-value">{openPorts.length}</span>
            </div>
            <div className="stat-card stat-filtered">
              <span className="stat-label">Filtered</span>
              <span className="stat-value">{filteredPorts.length}</span>
            </div>
            <div className="stat-card stat-closed">
              <span className="stat-label">Closed</span>
              <span className="stat-value">{closedPorts.length}</span>
            </div>
          </div>
          {results.length === 0 ? (
            <div className="no-results-message text-center text-muted py-8">
              No ports found for this scan.
            </div>
          ) : (
            <div className="ports-grid grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
              {results.map(result => (
                <div
                  key={result.port + result.status}
                  className={`port-card card--glass border shadow-md flex flex-col gap-2 ${result.status}`}
                  style={{ minWidth: 0 }}
                >
                  <div className="flex-between">
                    <span className={`badge badge-${result.status}`}>{result.status.toUpperCase()}</span>
                    {result.status === 'open' && (
                      <button
                        className="copy-btn"
                        onClick={() => copyToClipboard(result.port)}
                        title="Copy port number"
                      >
                        <Copy size={14} />
                        {copiedPort === result.port ? 'Copied!' : 'Copy'}
                      </button>
                    )}
                  </div>
                  <div className="port-info">
                    <span className="port-number text-lg font-bold">Port {result.port}</span>
                    <span className="port-service text-sm">{result.service || 'Unknown'}</span>
                  </div>
                  {result.banner && (
                    <span className="port-banner text-xs text-muted">{result.banner}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!isScanning && results.length === 0 && !progress && (
        <div className="empty-state flex flex-col items-center justify-center py-12">
          <div className="empty-icon mb-4">
            <Wifi size={48} />
          </div>
          <h3 className="text-2xl font-semibold mb-2">Ready to Scan</h3>
          <p className="mb-4 text-center">Enter a target host and port range to discover open ports and running services.</p>
          <div className="quick-tips bg-card p-4 rounded-lg shadow-md w-full max-w-md">
            <p className="tips-title font-semibold mb-2">Quick Tips:</p>
            <ul className="grid grid-cols-2 gap-2 text-sm">
              <li>Quick scan: 1-1000 (top 1000 ports)</li>
              <li>Common services: 21-443, 3306, 5432, 8080</li>
              <li>Full scan: 1-65535 (all ports, slower)</li>
              <li>Specific ports: 22, 80, 443, 3306, 5432</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
