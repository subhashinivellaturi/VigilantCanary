import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, AlertCircle, Loader2, Search, CheckCircle, Eye } from 'lucide-react';
import { Card } from './ui/Card';
import { API_URL } from '../api/client';

interface SubdomainResult {
  status: string;
  domain: string;
  subdomains?: string[];
  total_found?: number;
  scan_time?: number;
  method?: string;
  scan_id?: number;
  message?: string;
}

interface SubdomainEnumerationPanelProps {
  limit?: number;
  compact?: boolean;
}

export function SubdomainEnumerationPanel({ limit = 5, compact = false }: SubdomainEnumerationPanelProps) {
  const [baseDomain, setBaseDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SubdomainResult | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleEnumerate = async () => {
    const domainRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/i;
    
    if (!baseDomain.trim()) {
      setError('Please enter a domain');
      return;
    }

    if (!domainRegex.test(baseDomain.trim())) {
      setError('Invalid domain format (e.g., example.com)');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/enumerate-subdomains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          base_domain: baseDomain.trim(),
          use_brute_force: true
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
      
      if (data.status !== 'success') {
        setError(data.message || 'Enumeration failed');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to enumerate subdomains');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleCopySubdomain = (subdomain: string, index: number) => {
    navigator.clipboard.writeText(subdomain);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !loading && baseDomain.trim()) {
      handleEnumerate();
    }
  };

  if (compact) {
    return (
      <Card title="Quick Subdomain Enum" className="p-4">
        <div className="space-y-4">
          <div className="flex gap-2">
            <input
              type="text"
              value={baseDomain}
              onChange={(e) => setBaseDomain(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com"
              disabled={loading}
              className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-purple-500"
            />
            <button
              onClick={handleEnumerate}
              disabled={loading || !baseDomain.trim()}
              className="px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white text-sm rounded-lg transition-colors"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </button>
          </div>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-sm text-red-400">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}

          {result && result.status === 'success' && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-sm text-green-400">
                  Found {result.total_found} subdomain{result.total_found !== 1 ? 's' : ''}
                </span>
              </div>
              {result.subdomains && result.subdomains.length > 0 && (
                <div className="max-h-40 overflow-y-auto space-y-1">
                  {result.subdomains.slice(0, limit).map((subdomain, i) => (
                    <div key={i} className="flex items-center justify-between px-2 py-1 bg-slate-700/50 rounded text-xs text-slate-300 group hover:bg-slate-700 transition">
                      <code className="font-mono">{subdomain}</code>
                      <button
                        onClick={() => handleCopySubdomain(subdomain, i)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                        title="Copy"
                      >
                        {copiedIndex === i ? (
                          <CheckCircle className="h-3 w-3 text-green-400" />
                        ) : (
                          <Eye className="h-3 w-3 text-slate-400" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </Card>
    );
  }

  // Full view
  return (
    <Card title="Subdomain Enumeration" className="p-6">
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-purple-500/20 rounded-lg">
            <Globe className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Discover Subdomains</h3>
            <p className="text-sm text-slate-400">Enumerate subdomains using DNS brute force</p>
          </div>
        </div>

        <div className="space-y-3">
          <label className="block text-sm font-medium text-slate-300">Base Domain</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={baseDomain}
              onChange={(e) => setBaseDomain(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com"
              disabled={loading}
              className="flex-1 px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 disabled:opacity-50"
            />
            <button
              onClick={handleEnumerate}
              disabled={loading || !baseDomain.trim()}
              className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-all duration-200 flex items-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Enumerate
                </>
              )}
            </button>
          </div>
          <p className="text-xs text-slate-500">Enter the root domain to discover associated subdomains</p>
        </div>

        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3"
            >
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-red-400">Error</h4>
                <p className="text-sm text-red-300">{error}</p>
              </div>
            </motion.div>
          )}

          {result && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-4"
            >
              {result.status === 'success' ? (
                <>
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="p-4 bg-slate-700/30 border border-slate-600/30 rounded-lg">
                      <div className="text-2xl font-bold text-green-400">{result.total_found}</div>
                      <div className="text-xs text-slate-400">Subdomains Found</div>
                    </div>
                    <div className="p-4 bg-slate-700/30 border border-slate-600/30 rounded-lg">
                      <div className="text-2xl font-bold text-blue-400">{result.scan_time}s</div>
                      <div className="text-xs text-slate-400">Scan Time</div>
                    </div>
                    <div className="p-4 bg-slate-700/30 border border-slate-600/30 rounded-lg">
                      <div className="text-2xl font-bold text-purple-400">{result.method}</div>
                      <div className="text-xs text-slate-400">Method</div>
                    </div>
                  </div>

                  {result.subdomains && result.subdomains.length > 0 ? (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-3">Discovered Subdomains</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-80 overflow-y-auto">
                        {result.subdomains.map((subdomain, i) => (
                          <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.05 }}
                            className="flex items-center justify-between px-3 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg group hover:bg-slate-700/70 transition"
                          >
                            <code className="font-mono text-sm text-slate-300">{subdomain}</code>
                            <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button
                                onClick={() => handleCopySubdomain(subdomain, i)}
                                title="Copy subdomain"
                                className="p-1 hover:bg-slate-600/50 rounded"
                              >
                                {copiedIndex === i ? (
                                  <CheckCircle className="h-4 w-4 text-green-400" />
                                ) : (
                                  <Eye className="h-4 w-4 text-slate-400" />
                                )}
                              </button>
                              <a
                                href={`http://${subdomain}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                title="Open in browser"
                                className="p-1 hover:bg-slate-600/50 rounded"
                              >
                                <Eye className="h-4 w-4 text-slate-400" />
                              </a>
                            </div>
                          </motion.div>
                        ))}
                      </div>
                      {result.subdomains.length > limit && (
                        <p className="text-xs text-slate-500 mt-2">
                          Showing {Math.min(limit, result.subdomains.length)} of {result.subdomains.length} subdomains
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="p-4 bg-slate-700/30 border border-slate-600/30 rounded-lg text-center">
                      <p className="text-slate-400 text-sm">No subdomains discovered</p>
                    </div>
                  )}
                </>
              ) : (
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <p className="text-red-400 text-sm">{result.message || 'Enumeration failed'}</p>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Card>
  );
}
