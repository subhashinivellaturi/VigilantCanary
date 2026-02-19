import React, { useState, lazy, Suspense } from "react";
import { motion } from "framer-motion";
import { Globe, AlertCircle, Loader2, Search, CheckCircle } from "lucide-react";
import { Card } from './ui/Card';
import { EmptyState } from './ui/EmptyState';
import { Badge } from './ui/Badge';
import { useToast } from './ui/Toast';
// Chatbot is now provided in the global sidebar

import { API_URL } from "../api/client";

export function SubdomainFinder() {
  const [baseDomain, setBaseDomain] = useState("");
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [subdomainError, setSubdomainError] = useState<string | null>(null);
  const [subdomainResult, setSubdomainResult] = useState<any>(null);

  const toast = useToast();

  const handleSubdomainEnumeration = async () => {
    const domainRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/i;
    if (!baseDomain.trim() || !domainRegex.test(baseDomain)) {
      setSubdomainError("Please enter a valid base domain (ex: example.com)");
      toast.showToast('Please enter a valid base domain', 'error');
      return;
    }

    setSubdomainLoading(true);
    setSubdomainError(null);
    setSubdomainResult(null);

    try {
      const response = await fetch(`${API_URL}/enumerate-subdomains`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          base_domain: baseDomain,
          use_brute_force: true,
        }),
      });

      if (!response.ok) {
        throw new Error(`Subdomain enumeration failed: ${response.statusText}`);
      }

      const data = await response.json();
      setSubdomainResult(data);
    } catch (err) {
      setSubdomainError(err instanceof Error ? err.message : "Subdomain enumeration failed");
    } finally {
      setSubdomainLoading(false);
    }
  };

  const handleSubdomainKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !subdomainLoading) {
      handleSubdomainEnumeration();
    }
  };

  return (
    <div className="space-y-8">
      {/* Subdomain Enumeration Section */}
      <Card title="Subdomain Enumeration" subtitle="Discover hidden subdomains and expand your attack surface" className="p-8">
        <div className="flex items-center space-x-4 mb-8">
          <div className="p-3 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl">
            <Globe className="h-8 w-8 text-purple-400" />
          </div>
          <div>
            <h2 className="text-3xl font-bold text-white">Subdomain Enumeration</h2>
            <p className="text-slate-400 text-lg">Discover hidden subdomains and expand your attack surface</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-6">
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-slate-300 mb-3 flex items-center space-x-2">
                <Search className="h-4 w-4 text-purple-400" />
                <span>Base Domain</span>
              </label>
              <div className="relative group">
                <input
                  type="text"
                  value={baseDomain}
                  onChange={(e) => setBaseDomain(e.target.value)}
                  onKeyPress={handleSubdomainKeyPress}
                  placeholder="example.com"
                  className="w-full px-5 py-4 bg-slate-700/50 border border-slate-600/50 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-200 text-lg hover:bg-slate-700/70"
                  disabled={subdomainLoading}
                />
                <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 to-pink-500/5 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none"></div>
              </div>
              <p className="text-slate-500 text-sm">Enter the root domain to discover all associated subdomains</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-700/30 border border-slate-600/30 rounded-xl p-4">
                <div className="text-2xl font-bold text-purple-400">100+</div>
                <div className="text-slate-400 text-sm">Wordlist Size</div>
              </div>
              <div className="bg-slate-700/30 border border-slate-600/30 rounded-xl p-4">
                <div className="text-2xl font-bold text-pink-400">~2m</div>
                <div className="text-slate-400 text-sm">Scan Time</div>
              </div>
              <div className="bg-slate-700/30 border border-slate-600/30 rounded-xl p-4">
                <div className="text-2xl font-bold text-indigo-400">DNS</div>
                <div className="text-slate-400 text-sm">Resolution</div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Enumeration Methods</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 text-sm">Brute Force</span>
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 text-sm">DNS Resolution</span>
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 text-sm">Certificate Transparency</span>
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 text-sm">Public Records</span>
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
              </div>
            </div>

            <button
              onClick={handleSubdomainEnumeration}
              disabled={subdomainLoading || !baseDomain.trim()}
              className="w-full relative group bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 disabled:cursor-not-allowed px-8 py-5 rounded-xl text-white font-bold text-lg transition-all duration-200 shadow-lg hover:shadow-xl hover:shadow-purple-500/25 hover:-translate-y-0.5 disabled:hover:translate-y-0 disabled:hover:shadow-none"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-200"></div>
              <div className="relative flex items-center justify-center space-x-3">
                {subdomainLoading ? (
                  <>
                    <Loader2 className="h-6 w-6 animate-spin" />
                    <span>Finding Subdomains...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-6 w-6" />
                    <span>Start Enumeration</span>
                  </>
                )}
              </div>
            </button>

            <div className="text-center">
              <p className="text-slate-500 text-sm">
                Enumeration completes in <span className="text-purple-400 font-medium">1-3 minutes</span>
              </p>
            </div>
          </div>
        </div>

        {subdomainError && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mt-6 p-6 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-xl"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-red-500/20 rounded-lg">
                <AlertCircle className="h-6 w-6 text-red-400" />
              </div>
              <div>
                <h3 className="text-red-400 font-semibold text-lg">Enumeration Error</h3>
                <p className="text-red-300 mt-1">{subdomainError}</p>
              </div>
            </div>
          </motion.div>
        )}
      </Card>

      {/* Results Section */}
      {subdomainResult && (
        <Card title="Subdomain Enumeration Results" className="p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Subdomain Enumeration Results</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-2xl font-bold text-blue-400">{subdomainResult.total_found || 0}</div>
              <div className="text-sm text-slate-400">Subdomains Found</div>
            </div>
            <div className="bg-slate-700 rounded-lg p-4">
              <div className="text-2xl font-bold text-green-400">{subdomainResult.discovered_subdomains?.length || 0}</div>
              <div className="text-sm text-slate-400">Discovered</div>
            </div>
          </div>

          {subdomainResult.discovered_subdomains && subdomainResult.discovered_subdomains.length > 0 ? (
            <div>
              <h4 className="text-md font-semibold text-white mb-3">Discovered Subdomains</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {subdomainResult.discovered_subdomains.map((subdomain: string, index: number) => (
                  <div key={index} className="flex items-center space-x-3 bg-slate-700 rounded-lg p-3">
                    <div className="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center">
                      <Globe className="h-4 w-4 text-white" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white truncate">{subdomain}</div>
                      <Badge variant="success" size="sm">Active</Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState
              icon={<Globe size={48} />}
              title="No Subdomains Found"
              description="No subdomains were discovered during the enumeration process."
            />
          )}
        </Card>
      )}

      {/* Chatbot removed from this page — use the global sidebar assistant */}
    </div>
  );
}