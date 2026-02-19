import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Copy, CheckCircle, Clock, AlertCircle, Loader2, Trash2, Eye } from 'lucide-react';
import { Card } from './ui/Card';
import { API_URL } from '../api/client';

interface SubdomainScan {
  id: number;
  timestamp: string;
  base_domain: string;
  discovered_subdomains: string[];
  total_found: number;
  scan_method: string;
  status: string;
}

export function SubdomainScanHistory() {
  const [scans, setScans] = useState<SubdomainScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedScan, setExpandedScan] = useState<number | null>(null);
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  useEffect(() => {
    fetchSubdomainScanHistory();
  }, []);

  const fetchSubdomainScanHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`${API_URL}/recent-subdomain-scans?limit=10`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success' && data.scans) {
        setScans(data.scans);
      } else {
        setScans([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch subdomain scan history');
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, domain: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDomain(domain);
    setTimeout(() => setCopiedDomain(null), 2000);
  };

  const formatDate = (isoDate: string) => {
    try {
      const date = new Date(isoDate);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Invalid date';
    }
  };

  const exportSubdomainsPDF = async (scan: SubdomainScan) => {
    // Dynamically import jsPDF
    const { jsPDF } = await import('jspdf');
    const pdf = new jsPDF();
    const margin = 20;
    let yPosition = margin;

    pdf.setFontSize(18);
    pdf.text('Subdomain Scan Report', margin, yPosition);
    yPosition += 12;

    pdf.setFontSize(12);
    pdf.text(`Domain: ${scan.base_domain}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Scan Date: ${formatDate(scan.timestamp)}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Scan Method: ${scan.scan_method}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Status: ${scan.status}`, margin, yPosition);
    yPosition += 8;
    pdf.text(`Total Subdomains Found: ${scan.total_found}`, margin, yPosition);
    yPosition += 10;

    pdf.setFontSize(14);
    pdf.text('Discovered Subdomains:', margin, yPosition);
    yPosition += 8;
    pdf.setFontSize(10);
    if (scan.discovered_subdomains.length > 0) {
      scan.discovered_subdomains.forEach((sub, idx) => {
        pdf.text(`- ${sub}`, margin + 5, yPosition);
        yPosition += 6;
        if (yPosition > pdf.internal.pageSize.getHeight() - margin) {
          pdf.addPage();
          yPosition = margin;
        }
      });
    } else {
      pdf.text('No subdomains discovered.', margin + 5, yPosition);
    }

    pdf.save(`subdomains-${scan.base_domain}-${new Date().getTime()}.pdf`);
  };

  const deleteScan = (scanId: number) => {
    if (window.confirm('Delete this subdomain scan record?')) {
      setScans(scans.filter(s => s.id !== scanId));
    }
  };

  if (loading) {
    return (
      <Card title="Subdomain Scan History" subtitle="View your previous subdomain discoveries">
        <div className="flex flex-col items-center justify-center py-12">
          <Loader2 className="h-6 w-6 text-purple-400 animate-spin mb-4" />
          <p className="text-slate-400">Loading scan history...</p>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card title="Subdomain Scan History" subtitle="View your previous subdomain discoveries">
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-400 font-medium">Error Loading History</p>
            <p className="text-red-300 text-sm">{error}</p>
            <button
              onClick={fetchSubdomainScanHistory}
              className="mt-3 px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </Card>
    );
  }

  if (scans.length === 0) {
    return (
      <Card title="Subdomain Scan History" subtitle="View your previous subdomain discoveries">
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="p-4 bg-purple-500/10 rounded-full mb-4">
            <Globe className="h-8 w-8 text-purple-400" />
          </div>
          <p className="text-slate-400 text-lg font-medium">No subdomain scans yet</p>
          <p className="text-slate-500 text-sm">Use the Subdomain Enumeration panel to discover subdomains</p>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Subdomain Scan History" subtitle={`${scans.length} recent scan${scans.length !== 1 ? 's' : ''}`}>
      <div className="space-y-4">
        <AnimatePresence mode="popLayout">
          {scans.map((scan, index) => (
            <motion.div
              key={scan.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ delay: index * 0.05 }}
              className="border border-slate-600/30 rounded-lg overflow-hidden hover:border-purple-500/50 transition-all"
            >
              {/* Card Header */}
              <button
                onClick={() => setExpandedScan(expandedScan === scan.id ? null : scan.id)}
                className="w-full p-4 bg-slate-700/20 hover:bg-slate-700/40 transition-colors flex items-center justify-between"
              >
                <div className="flex items-center gap-3 text-left flex-1">
                  <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Globe className="h-4 w-4 text-purple-400" />
                  </div>
                  <div>
                    <div className="font-semibold text-white">{scan.base_domain}</div>
                    <div className="text-xs text-slate-400 flex items-center gap-2 mt-1">
                      <Clock className="h-3 w-3" />
                      {formatDate(scan.timestamp)}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-sm font-bold text-green-400">{scan.total_found}</div>
                    <div className="text-xs text-slate-400">subdomains</div>
                  </div>
                  <div className={`transform transition-transform ${expandedScan === scan.id ? 'rotate-180' : ''}`}>
                    <Eye className="h-4 w-4 text-slate-400" />
                  </div>
                </div>
              </button>

              {/* Card Content - Expanded */}
              <AnimatePresence>
                {expandedScan === scan.id && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                    className="border-t border-slate-600/30 p-4 bg-slate-800/20"
                  >
                    {/* Scan Metadata */}
                    <div className="grid grid-cols-3 gap-3 mb-4">
                      <div className="p-3 bg-slate-700/30 rounded-lg">
                        <div className="text-xs text-slate-400">Method</div>
                        <div className="text-sm font-medium text-white mt-1">{scan.scan_method}</div>
                      </div>
                      <div className="p-3 bg-slate-700/30 rounded-lg">
                        <div className="text-xs text-slate-400">Status</div>
                        <div className="flex items-center gap-2 text-sm font-medium text-green-400 mt-1">
                          <CheckCircle className="h-3 w-3" />
                          {scan.status}
                        </div>
                      </div>
                      <div className="p-3 bg-slate-700/30 rounded-lg">
                        <div className="text-xs text-slate-400">Total Found</div>
                        <div className="text-sm font-medium text-blue-400 mt-1">{scan.total_found}</div>
                      </div>
                    </div>

                    {/* Subdomains List */}
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                        <Globe className="h-4 w-4 text-purple-400" />
                        Discovered Subdomains
                      </h4>
                      <div className="max-h-64 overflow-y-auto space-y-2 pr-2">
                        {scan.discovered_subdomains && scan.discovered_subdomains.length > 0 ? (
                          scan.discovered_subdomains.map((subdomain, i) => (
                            <motion.div
                              key={i}
                              initial={{ opacity: 0, x: -10 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: i * 0.02 }}
                              className="flex items-center justify-between px-3 py-2 bg-slate-700/40 rounded-lg hover:bg-slate-700/60 group transition-colors"
                            >
                              <code className="text-xs font-mono text-slate-300">{subdomain}</code>
                              <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <button
                                  onClick={() => copyToClipboard(subdomain, subdomain)}
                                  title="Copy subdomain"
                                  className="p-1 hover:bg-slate-600/50 rounded transition-colors"
                                >
                                  {copiedDomain === subdomain ? (
                                    <CheckCircle className="h-3 w-3 text-green-400" />
                                  ) : (
                                    <Copy className="h-3 w-3 text-slate-400" />
                                  )}
                                </button>
                                <a
                                  href={`http://${subdomain}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="p-1 hover:bg-slate-600/50 rounded transition-colors"
                                  title="Open in browser"
                                >
                                  <Globe className="h-3 w-3 text-purple-400" />
                                </a>
                              </div>
                            </motion.div>
                          ))
                        ) : (
                          <p className="text-xs text-slate-500 py-4 text-center">No subdomains discovered</p>
                        )}
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex gap-2 mt-4 pt-4 border-t border-slate-600/30">
                      <button
                        onClick={() => exportSubdomainsPDF(scan)}
                        className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg text-sm font-medium transition-colors"
                      >
                        <Copy className="h-4 w-4" />
                        Export PDF
                      </button>
                      <button
                        onClick={() => copyToClipboard(scan.discovered_subdomains.join('\n'), 'all')}
                        className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 rounded-lg text-sm font-medium transition-colors"
                      >
                        <Copy className="h-4 w-4" />
                        Copy All
                      </button>
                      <button
                        onClick={() => deleteScan(scan.id)}
                        className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg text-sm font-medium transition-colors"
                        title="Delete scan"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Refresh Button */}
        <button
          onClick={fetchSubdomainScanHistory}
          className="w-full px-4 py-2 bg-slate-700/30 hover:bg-slate-700/50 text-slate-400 hover:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 mt-4"
        >
          <Loader2 className="h-4 w-4" />
          Refresh History
        </button>
      </div>
    </Card>
  );
}

export default SubdomainScanHistory;
