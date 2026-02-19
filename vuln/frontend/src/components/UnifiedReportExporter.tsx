import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Download, Eye, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import { Card } from './ui/Card';
import { API_URL } from '../api/client';

interface UnifiedReportExporterProps {
  title?: string;
  subtitle?: string;
  compact?: boolean;
}

export function UnifiedReportExporter({ 
  title = "Export Unified Report",
  subtitle = "Download security report in your preferred format",
  compact = false 
}: UnifiedReportExporterProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async (format: 'pdf' | 'csv' | 'html') => {
    setLoading(format);
    setError(null);
    setSuccess(null);

    try {
      // For PDF, we need to fetch JSON and generate client-side
      if (format === 'pdf') {
        const response = await fetch(`${API_URL}/unified-report?format=json`);
        if (!response.ok) {
          throw new Error('Failed to fetch report data');
        }
        
        const reportData = await response.json();
        await generatePDFReport(reportData);
        setSuccess('PDF report generated successfully!');
      } else {
        // For CSV and HTML, fetch directly from backend
        const response = await fetch(`${API_URL}/unified-report?format=${format}`);
        if (!response.ok) {
          throw new Error(`Failed to export as ${format.toUpperCase()}`);
        }
        // Get the filename from Content-Disposition header
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `unified-security-report.${format}`;
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename=([^;\n]+)/);
          if (filenameMatch) {
            filename = filenameMatch[1].replace(/"/g, '');
          }
        }
        // Download the file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        setSuccess(`${format.toUpperCase()} report exported successfully!`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to export as ${format.toUpperCase()}`);
    } finally {
      setLoading(null);
      
      // Clear success message after 3 seconds
      if (!error) {
        setTimeout(() => setSuccess(null), 3000);
      }
    }
  };

  const handlePreview = async () => {
    setLoading('preview');
    setError(null);

    try {
      const response = await fetch(`${API_URL}/unified-report/preview`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch report preview');
      }

      const html = await response.text();
      
      // Open preview in new window
      const previewWindow = window.open('', '_blank');
      if (previewWindow) {
        previewWindow.document.write(html);
        previewWindow.document.close();
      } else {
        throw new Error('Could not open preview window. Please check popup blockers.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to open preview');
    } finally {
      setLoading(null);
    }
  };

  // Generate PDF client-side (for better compatibility)
  const generatePDFReport = async (reportData: any) => {
    try {
      // Dynamic import of jsPDF to avoid loading it if not needed
      const { jsPDF } = await import('jspdf');
      
      const pdf = new jsPDF();
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 20;
      const contentWidth = pageWidth - (margin * 2);
      let yPosition = margin;

      const addText = (text: string, x: number, y: number, fontSize: number = 10, isBold: boolean = false) => {
        pdf.setFontSize(fontSize);
        pdf.setFont('helvetica', isBold ? 'bold' : 'normal');
        pdf.text(text, x, y);
        return y + (fontSize * 0.6) + 2;
      };

      const addWrappedText = (text: string, x: number, y: number, maxWidth: number, fontSize: number = 10) => {
        pdf.setFontSize(fontSize);
        const lines = pdf.splitTextToSize(text, maxWidth);
        pdf.text(lines, x, y);
        return y + (lines.length * (fontSize * 0.5)) + 3;
      };

      const checkPageBreak = (requiredSpace: number) => {
        if (yPosition + requiredSpace > pageHeight - margin) {
          pdf.addPage();
          yPosition = margin;
        }
      };

      const addSectionHeader = (title: string) => {
        checkPageBreak(15);
        pdf.setDrawColor(102, 126, 234);
        pdf.line(margin, yPosition + 2, pageWidth - margin, yPosition + 2);
        yPosition = addText(title, margin, yPosition, 14, true);
        yPosition += 5;
        return yPosition;
      };

      // Title Section
      pdf.setFillColor(102, 126, 234);
      pdf.rect(0, 0, pageWidth, 40, 'F');
      pdf.setTextColor(255, 255, 255);
      yPosition = addText('Unified Security Report', margin, 20, 20, true);
      pdf.setTextColor(0, 0, 0);
      yPosition = margin + 45;

      // Generation info
      yPosition = addText(
        `Generated: ${new Date(reportData.report_metadata?.generated_at || new Date()).toLocaleString()}`,
        margin,
        yPosition,
        9
      );
      yPosition += 8;

      // Executive Summary
      yPosition = addSectionHeader('Executive Summary');
      
      const summary = reportData.scan_summary || {};
      const severityBreakdown = reportData.severity_breakdown || { critical: 0, high: 0, medium: 0, low: 0 };
      const totalVulnerabilities = severityBreakdown.critical + severityBreakdown.high + severityBreakdown.medium + severityBreakdown.low;
      
      const summaryData = [
        `Total Scans Performed: ${summary.total_scans || 0}`,
        `Total Vulnerabilities Found: ${totalVulnerabilities}`,
        `- Critical: ${severityBreakdown.critical || 0}`,
        `- High: ${severityBreakdown.high || 0}`,
        `- Medium: ${severityBreakdown.medium || 0}`,
        `- Low: ${severityBreakdown.low || 0}`,
        `Open Ports Detected: ${summary.total_ports_scanned || 0}`,
        `Subdomains Discovered: ${summary.total_subdomains_found || 0}`
      ];

      summaryData.forEach(info => {
        yPosition = addText(info, margin + 5, yPosition, 9);
      });
      yPosition += 12;

      // Severity Breakdown Chart (text-based)
      if (totalVulnerabilities > 0) {
        yPosition = addSectionHeader('Threat Level Breakdown');
        
        const severities = [
          { level: 'Critical', count: severityBreakdown.critical, color: [220, 38, 38] },
          { level: 'High', count: severityBreakdown.high, color: [239, 68, 68] },
          { level: 'Medium', count: severityBreakdown.medium, color: [245, 158, 11] },
          { level: 'Low', count: severityBreakdown.low, color: [34, 197, 94] }
        ];

        severities.forEach(sev => {
          if (sev.count > 0) {
            const percentage = Math.round((sev.count / totalVulnerabilities) * 100);
            const barLength = (percentage / 100) * 100;
            
            // Draw bar background
            pdf.setDrawColor(200, 200, 200);
            pdf.rect(margin + 30, yPosition - 2, 80, 5);
            
            // Draw bar filled
            pdf.setFillColor(sev.color[0], sev.color[1], sev.color[2]);
            pdf.rect(margin + 30, yPosition - 2, (barLength * 80) / 100, 5, 'F');
            
            yPosition = addText(`${sev.level}: ${sev.count} (${percentage}%)`, margin + 5, yPosition, 9);
          }
        });
        yPosition += 10;
      } else {
        yPosition = addText('No vulnerabilities detected in current scans.', margin + 5, yPosition, 9);
        yPosition += 10;
      }

      // Vulnerabilities Section
      if (reportData.vulnerabilities && reportData.vulnerabilities.length > 0) {
        yPosition = addSectionHeader('Detected Vulnerabilities');
        
        const vulnerabilitiesToShow = reportData.vulnerabilities.slice(0, 15);
        
        vulnerabilitiesToShow.forEach((vuln: any, index: number) => {
          checkPageBreak(20);
          yPosition = addText(
            `${index + 1}. ${vuln.vulnerability_name || 'Unknown Vulnerability'}`,
            margin + 5,
            yPosition,
            10,
            true
          );
          
          const severity = (vuln.severity || 'unknown').toUpperCase();
          const cvss = vuln.cvss_score || 'N/A';
          yPosition = addText(`Severity: ${severity} | CVSS: ${cvss}`, margin + 10, yPosition, 8);
          
          if (vuln.affected_url) {
            yPosition = addWrappedText(`URL: ${vuln.affected_url}`, margin + 10, yPosition, contentWidth - 15, 8);
          }
          
          if (vuln.description) {
            yPosition = addWrappedText(`Description: ${vuln.description}`, margin + 10, yPosition, contentWidth - 15, 8);
          }
          
          yPosition += 3;
        });

        if (reportData.vulnerabilities.length > 15) {
          yPosition = addText(
            `... and ${reportData.vulnerabilities.length - 15} more vulnerabilities`,
            margin,
            yPosition,
            9
          );
          yPosition += 8;
        }
      } else {
        checkPageBreak(15);
        yPosition = addSectionHeader('Vulnerabilities');
        yPosition = addText('No vulnerabilities detected in current scans.', margin + 5, yPosition, 9);
        yPosition += 10;
      }

      // Port Scans Section
      if (reportData.port_scans && reportData.port_scans.length > 0) {
        yPosition = addSectionHeader('Open Ports Detected');
        
        reportData.port_scans.slice(0, 10).forEach((scan: any) => {
          checkPageBreak(15);
          yPosition = addText(`Target: ${scan.target_host}`, margin + 5, yPosition, 9);
          
          const portsText = scan.open_ports?.map((p: any) => `${p.port}/${p.protocol}`).join(', ') || 'N/A';
          yPosition = addWrappedText(
            `Open Ports: ${portsText}`,
            margin + 10,
            yPosition,
            contentWidth - 15,
            8
          );
          
          yPosition += 3;
        });
      }

      // Subdomains Section
      if (reportData.subdomain_scans && reportData.subdomain_scans.length > 0) {
        yPosition = addSectionHeader('Discovered Subdomains');
        
        reportData.subdomain_scans.slice(0, 10).forEach((scan: any) => {
          checkPageBreak(15);
          yPosition = addText(`Domain: ${scan.base_domain}`, margin + 5, yPosition, 9);
          yPosition = addText(`Total Found: ${scan.total_found || 0}`, margin + 10, yPosition, 8);
          
          if (scan.discovered_subdomains && scan.discovered_subdomains.length > 0) {
            const sampleDomains = scan.discovered_subdomains.slice(0, 5).join(', ');
            yPosition = addWrappedText(
              `Samples: ${sampleDomains}${scan.discovered_subdomains.length > 5 ? '...' : ''}`,
              margin + 10,
              yPosition,
              contentWidth - 15,
              8
            );
          }
          
          yPosition += 3;
        });
      }

      // Recommendations Section
      checkPageBreak(30);
      yPosition = addSectionHeader('Security Recommendations');
      
      const recommendations = [
        '• Review and remediate all critical and high-severity vulnerabilities immediately',
        '• Implement Web Application Firewall (WAF) for identified web vulnerabilities',
        '• Conduct regular security audits and penetration testing',
        '• Keep all software and dependencies up to date with latest patches',
        '• Implement strong authentication and access control mechanisms',
        '• Monitor system logs for suspicious activity and unauthorized access attempts',
        '• Establish incident response procedures and security incident notification process'
      ];

      recommendations.forEach(rec => {
        yPosition = addWrappedText(rec, margin + 5, yPosition, contentWidth - 10, 9);
      });

      // Footer with page numbers
      const pageCount = pdf.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        pdf.setPage(i);
        pdf.setFontSize(8);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor(128, 128, 128);
        pdf.text(
          `Page ${i} of ${pageCount}`,
          margin,
          pageHeight - 10
        );
        pdf.text(
          `Generated on ${new Date().toLocaleString()}`,
          pageWidth - 80,
          pageHeight - 10
        );
      }

      // Save PDF
      pdf.save(`unified-security-report-${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (err) {
      throw err;
    }
  };

  if (compact) {
    return (
      <Card title="Export Report" className="p-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {[
            { format: 'pdf', label: 'PDF', icon: Download },
            { format: 'html', label: 'Preview', icon: Eye }
          ].map(({ format, label, icon: Icon }) => (
            <button
              key={format}
              onClick={() => format === 'html' ? handlePreview() : handleExport(format as any)}
              disabled={!!loading}
              className="flex items-center justify-center gap-2 px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white text-sm rounded-lg transition-colors"
              title={`Export as ${label}`}
            >
              {loading === format || loading === 'preview' ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Icon className="h-4 w-4" />
              )}
              <span className="hidden sm:inline">{label}</span>
            </button>
          ))}
        </div>

        <AnimatePresence>
          {success && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mt-3 p-2 bg-green-500/10 border border-green-500/30 rounded flex items-center gap-2 text-sm text-green-400"
            >
              <CheckCircle className="h-4 w-4" />
              {success}
            </motion.div>
          )}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mt-3 p-2 bg-red-500/10 border border-red-500/30 rounded flex items-center gap-2 text-sm text-red-400"
            >
              <AlertCircle className="h-4 w-4" />
              {error}
            </motion.div>
          )}
        </AnimatePresence>
      </Card>
    );
  }

  // Full view
  return (
    <Card title={title} subtitle={subtitle} className="p-6">
      <div className="space-y-6">
        <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-lg p-6">
          <h3 className="font-semibold text-white mb-4">Available Export Formats</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              {
                format: 'pdf',
                label: 'PDF',
                icon: Download,
                description: 'Professional formatted report for printing and sharing',
                color: 'bg-red-500/20 hover:bg-red-500/30'
              },
              {
                format: 'html',
                label: 'HTML Preview',
                icon: Eye,
                description: 'Interactive web-based report preview in browser',
                color: 'bg-purple-500/20 hover:bg-purple-500/30'
              }
            ].map(({ format, label, icon: Icon, description, color }) => (
              <motion.button
                key={format}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => format === 'html' ? handlePreview() : handleExport(format as any)}
                disabled={!!loading}
                className={`p-4 rounded-lg text-left transition-all ${color} border border-current border-opacity-30 disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                <div className="flex items-start justify-between mb-2">
                  {loading === format || (format === 'html' && loading === 'preview') ? (
                    <Loader2 className="h-5 w-5 animate-spin text-current" />
                  ) : (
                    <Icon className="h-5 w-5 text-current" />
                  )}
                  <span className="text-xs font-semibold text-current opacity-70">
                    {format.toUpperCase()}
                  </span>
                </div>
                <h4 className="font-semibold text-white mb-1">{label}</h4>
                <p className="text-sm text-slate-300">{description}</p>
              </motion.button>
            ))}
          </div>
        </div>

        <div className="bg-slate-700/30 border border-slate-600/30 rounded-lg p-4">
          <h4 className="font-semibold text-white mb-2">Report Contents</h4>
          <ul className="space-y-1 text-sm text-slate-300">
            <li>✓ Scan Summary Statistics</li>
            <li>✓ Severity Breakdown (Critical, High, Medium, Low)</li>
            <li>✓ Open Ports Detected</li>
            <li>✓ Discovered Subdomains</li>
            <li>✓ Vulnerabilities Detected</li>
            <li>✓ Recent Scan History</li>
            <li>✓ Full Unicode Support</li>
          </ul>
        </div>

        <AnimatePresence>
          {success && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg flex items-start gap-3"
            >
              <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-green-400">Success</h4>
                <p className="text-sm text-green-300">{success}</p>
              </div>
            </motion.div>
          )}
          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3"
            >
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-red-400">Error</h4>
                <p className="text-sm text-red-300">{error}</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Card>
  );
}
