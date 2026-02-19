import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

// Unified report data interface
export interface UnifiedSecurityReport {
  // Scan summary
  scan_timestamp: string;
  total_scans: number;
  last_scan_date: string;

  // Severity breakdown
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  // Open ports
  open_ports: Array<{
    id: number;
    timestamp: string;
    target_host: string;
    open_ports: Array<{
      port: number;
      service: string;
      protocol: string;
    }>;
    open_count: number;
    scan_method: string;
  }>;

  // Discovered subdomains
  discovered_subdomains: Array<{
    id: number;
    timestamp: string;
    base_domain: string;
    discovered_subdomains: string[];
    total_found: number;
    scan_method: string;
    status: string;
  }>;

  // Vulnerabilities detected
  vulnerabilities: Array<{
    id: string;
    timestamp: string;
    vulnerability_name: string;
    severity: string;
    affected_url: string;
    scan_type: string;
    cvss_score: number;
    description: string;
    confidence: number;
  }>;

  // Recent scans
  recent_scans: Array<{
    id: number;
    scan_timestamp: string;
    scanned_url: string;
    scan_mode: string;
    status: string;
    findings: number;
    severity_breakdown: Record<string, number>;
  }>;
}

interface ProductionScanResponse {
  status: string;
  scan_timestamp: string;
  scanned_url: string;
  scan_mode: string;
  findings: Array<{
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
  }>;
  finding_counts: Record<string, number>;
  severity_breakdown: Record<string, number>;
  executive_summary: {
    scan_timestamp: string;
    scanned_url: string;
    scan_mode: string;
    total_findings: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    overall_risk_status: string;
    risk_score_0_to_100: number;
    executive_summary_text: string;
    remediation_priority: string;
  };
  disclaimer: string;
}

export const generatePDFReport = async (scanData: ProductionScanResponse): Promise<void> => {
  const pdf = new jsPDF();
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const margin = 20;
  let yPosition = margin;

  // Helper function to add text with word wrapping
  const addWrappedText = (text: string, x: number, y: number, maxWidth: number, fontSize: number = 10) => {
    pdf.setFontSize(fontSize);
    const lines = pdf.splitTextToSize(text, maxWidth);
    pdf.text(lines, x, y);
    return y + (lines.length * fontSize * 0.4);
  };

  // Helper function to check if we need a new page
  const checkPageBreak = (requiredSpace: number) => {
    if (yPosition + requiredSpace > pageHeight - margin) {
      pdf.addPage();
      yPosition = margin;
    }
  };

  // Title
  pdf.setFontSize(20);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Vulnerability Scan Report', margin, yPosition);
  yPosition += 15;

  // Scan Information
  pdf.setFontSize(14);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Scan Information', margin, yPosition);
  yPosition += 10;

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(10);
  const scanInfo = [
    `URL: ${scanData.scanned_url}`,
    `Scan Mode: ${scanData.scan_mode}`,
    `Timestamp: ${new Date(scanData.scan_timestamp).toLocaleString()}`,
    `Status: ${scanData.status}`
  ];

  scanInfo.forEach(info => {
    pdf.text(info, margin, yPosition);
    yPosition += 6;
  });

  yPosition += 5;

  // Executive Summary
  checkPageBreak(60);
  pdf.setFontSize(14);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Executive Summary', margin, yPosition);
  yPosition += 10;

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(10);

  const summaryInfo = [
    `Total Findings: ${scanData.executive_summary.total_findings}`,
    `Critical: ${scanData.executive_summary.critical_count}`,
    `High: ${scanData.executive_summary.high_count}`,
    `Medium: ${scanData.executive_summary.medium_count}`,
    `Low: ${scanData.executive_summary.low_count}`,
    `Risk Status: ${scanData.executive_summary.overall_risk_status}`,
    `Risk Score: ${scanData.executive_summary.risk_score_0_to_100}/100`,
    `Remediation Priority: ${scanData.executive_summary.remediation_priority}`
  ];

  summaryInfo.forEach(info => {
    pdf.text(info, margin, yPosition);
    yPosition += 6;
  });

  yPosition += 5;

  // Executive Summary Text
  checkPageBreak(40);
  pdf.setFontSize(12);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Summary', margin, yPosition);
  yPosition += 8;

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(9);
  yPosition = addWrappedText(scanData.executive_summary.executive_summary_text, margin, yPosition, pageWidth - 2 * margin);

  // Findings Section
  if (scanData.findings.length > 0) {
    yPosition += 10;
    checkPageBreak(30);

    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Detailed Findings', margin, yPosition);
    yPosition += 10;

    scanData.findings.forEach((finding, index) => {
      checkPageBreak(80); // Ensure space for each finding

      // Finding header
      pdf.setFontSize(11);
      pdf.setFont('helvetica', 'bold');
      pdf.text(`${index + 1}. ${finding.vulnerability_type}`, margin, yPosition);
      yPosition += 8;

      // Finding details
      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(9);

      const details = [
        `Severity: ${finding.severity}`,
        `CVSS Score: ${finding.cvss_score}`,
        `Confidence: ${(finding.confidence * 100).toFixed(1)}%`,
        `OWASP Reference: ${finding.owasp_reference || 'N/A'}`
      ];

      if (finding.affected_url) details.push(`Affected URL: ${finding.affected_url}`);
      if (finding.affected_parameter) details.push(`Affected Parameter: ${finding.affected_parameter}`);
      if (finding.http_method) details.push(`HTTP Method: ${finding.http_method}`);

      details.forEach(detail => {
        pdf.text(detail, margin + 5, yPosition);
        yPosition += 5;
      });

      yPosition += 3;

      // Description
      if (finding.description) {
        pdf.setFont('helvetica', 'italic');
        yPosition = addWrappedText(`Description: ${finding.description}`, margin + 5, yPosition, pageWidth - 2 * margin - 10, 8);
        yPosition += 3;
      }

      // Payload information
      if (finding.payload_used) {
        pdf.setFont('helvetica', 'normal');
        yPosition = addWrappedText(`Payload Used: ${finding.payload_used}`, margin + 5, yPosition, pageWidth - 2 * margin - 10, 8);
        yPosition += 3;
      }

      // Remediation steps
      if (finding.remediation_steps && finding.remediation_steps.length > 0) {
        pdf.setFont('helvetica', 'bold');
        pdf.text('Remediation Steps:', margin + 5, yPosition);
        yPosition += 5;

        pdf.setFont('helvetica', 'normal');
        finding.remediation_steps.forEach((step, stepIndex) => {
          yPosition = addWrappedText(`${stepIndex + 1}. ${step}`, margin + 10, yPosition, pageWidth - 2 * margin - 15, 8);
        });
        yPosition += 5;
      }

      yPosition += 8; // Space between findings
    });
  }

  // Disclaimer
  if (scanData.disclaimer) {
    checkPageBreak(40);
    yPosition += 10;

    pdf.setFontSize(12);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Disclaimer', margin, yPosition);
    yPosition += 8;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(8);
    yPosition = addWrappedText(scanData.disclaimer, margin, yPosition, pageWidth - 2 * margin);
  }

  // Footer
  const pageCount = pdf.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    pdf.setPage(i);
    pdf.setFontSize(8);
    pdf.setFont('helvetica', 'normal');
    pdf.text(`Generated by Vigilant Canary - Page ${i} of ${pageCount}`, margin, pageHeight - 10);
    pdf.text(new Date().toLocaleString(), pageWidth - 60, pageHeight - 10);
  }

  // Save the PDF
  const fileName = `security-report-${new Date().toISOString().split('T')[0]}.pdf`;
  pdf.save(fileName);
};

// Fetch unified security report data from all endpoints
export const fetchUnifiedReportData = async (): Promise<UnifiedSecurityReport> => {
  const baseUrl = 'http://localhost:8005/api/v1';

  try {
    // Fetch all data in parallel
    const [
      severityResponse,
      portScansResponse,
      vulnerabilitiesResponse,
      subdomainScansResponse,
      recentScansResponse
    ] = await Promise.all([
      fetch(`${baseUrl}/dashboard/summary`),
      fetch(`${baseUrl}/recent-port-scans?limit=50`),
      fetch(`${baseUrl}/recent-vulnerabilities?limit=100`),
      fetch(`${baseUrl}/recent-subdomain-scans?limit=50`),
      fetch(`${baseUrl}/recent-scans?limit=20`)
    ]);

    // Parse responses
    const severityData = severityResponse.ok ? await severityResponse.json() : { severity_summary: { critical: 0, high: 0, medium: 0, low: 0 } };
    const portScansData = portScansResponse.ok ? await portScansResponse.json() : { scans: [] };
    const vulnerabilitiesData = vulnerabilitiesResponse.ok ? await vulnerabilitiesResponse.json() : { vulnerabilities: [] };
    const subdomainScansData = subdomainScansResponse.ok ? await subdomainScansResponse.json() : { scans: [] };
    const recentScansData = recentScansResponse.ok ? await recentScansResponse.json() : { scans: [] };

    // Calculate summary statistics
    const allScans = recentScansData.scans || [];
    const totalScans = allScans.length;
    const lastScanDate = allScans.length > 0 ? allScans[0].scan_timestamp : new Date().toISOString();

    return {
      scan_timestamp: new Date().toISOString(),
      total_scans: totalScans,
      last_scan_date: lastScanDate,
      severity_breakdown: severityData.severity_summary || { critical: 0, high: 0, medium: 0, low: 0 },
      open_ports: (portScansData.scans || []).filter((scan: any) => scan.open_count > 0),
      discovered_subdomains: subdomainScansData.scans || [],
      vulnerabilities: vulnerabilitiesData.vulnerabilities || [],
      recent_scans: allScans
    };
  } catch (error) {
    console.error('Error fetching unified report data:', error);
    // Return empty report structure on error
    return {
      scan_timestamp: new Date().toISOString(),
      total_scans: 0,
      last_scan_date: new Date().toISOString(),
      severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      open_ports: [],
      discovered_subdomains: [],
      vulnerabilities: [],
      recent_scans: []
    };
  }
};

// Generate PDF report from unified data
export const generateUnifiedPDFReport = async (reportData: UnifiedSecurityReport): Promise<void> => {
  const pdf = new jsPDF();
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();
  const margin = 20;
  let yPosition = margin;

  // Helper function to add text with word wrapping
  const addWrappedText = (text: string, x: number, y: number, maxWidth: number, fontSize: number = 10) => {
    pdf.setFontSize(fontSize);
    const lines = pdf.splitTextToSize(text, maxWidth);
    pdf.text(lines, x, y);
    return y + (lines.length * fontSize * 0.4);
  };

  // Helper function to check if we need a new page
  const checkPageBreak = (requiredSpace: number) => {
    if (yPosition + requiredSpace > pageHeight - margin) {
      pdf.addPage();
      yPosition = margin;
    }
  };

  // Title
  pdf.setFontSize(24);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Unified Security Report', margin, yPosition);
  yPosition += 20;

  // Report generation info
  pdf.setFontSize(10);
  pdf.setFont('helvetica', 'normal');
  pdf.text(`Generated: ${new Date(reportData.scan_timestamp).toLocaleString()}`, margin, yPosition);
  yPosition += 10;

  // Executive Summary
  checkPageBreak(60);
  pdf.setFontSize(16);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Executive Summary', margin, yPosition);
  yPosition += 12;

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(10);

  const summaryInfo = [
    `Total Scans: ${reportData.total_scans}`,
    `Last Scan Date: ${new Date(reportData.last_scan_date).toLocaleDateString()}`,
    `Critical Vulnerabilities: ${reportData.severity_breakdown.critical}`,
    `High Vulnerabilities: ${reportData.severity_breakdown.high}`,
    `Medium Vulnerabilities: ${reportData.severity_breakdown.medium}`,
    `Low Vulnerabilities: ${reportData.severity_breakdown.low}`,
    `Open Ports Detected: ${reportData.open_ports.length}`,
    `Subdomains Discovered: ${reportData.discovered_subdomains.reduce((sum, scan) => sum + scan.total_found, 0)}`,
    `Total Vulnerabilities: ${reportData.vulnerabilities.length}`
  ];

  summaryInfo.forEach(info => {
    pdf.text(info, margin, yPosition);
    yPosition += 6;
  });

  yPosition += 10;

  // Severity Breakdown Section
  checkPageBreak(40);
  pdf.setFontSize(14);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Severity Breakdown', margin, yPosition);
  yPosition += 10;

  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(10);

  const severityData = reportData.severity_breakdown;
  const severityLevels = [
    { level: 'Critical', count: severityData.critical, color: [220, 38, 38] },
    { level: 'High', count: severityData.high, color: [239, 68, 68] },
    { level: 'Medium', count: severityData.medium, color: [245, 158, 11] },
    { level: 'Low', count: severityData.low, color: [34, 197, 94] }
  ];

  severityLevels.forEach(severity => {
    pdf.setFillColor(severity.color[0], severity.color[1], severity.color[2]);
    pdf.rect(margin, yPosition - 4, 4, 4, 'F');
    pdf.text(`${severity.level}: ${severity.count}`, margin + 8, yPosition);
    yPosition += 6;
  });

  yPosition += 10;

  // Open Ports Section
  if (reportData.open_ports.length > 0) {
    checkPageBreak(50);
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Open Ports Detected', margin, yPosition);
    yPosition += 10;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);

    reportData.open_ports.slice(0, 10).forEach((scan, index) => {
      checkPageBreak(20);
      pdf.text(`${index + 1}. ${scan.target_host} (${scan.open_count} open ports)`, margin, yPosition);
      yPosition += 5;

      const portsText = scan.open_ports.slice(0, 5).map(p => `${p.port}/${p.protocol} (${p.service})`).join(', ');
      pdf.setFontSize(8);
      pdf.text(`   Ports: ${portsText}${scan.open_ports.length > 5 ? '...' : ''}`, margin + 5, yPosition);
      yPosition += 4;

      pdf.setFontSize(9);
      pdf.text(`   Scanned: ${new Date(scan.timestamp).toLocaleDateString()}`, margin + 5, yPosition);
      yPosition += 6;
    });

    if (reportData.open_ports.length > 10) {
      pdf.text(`... and ${reportData.open_ports.length - 10} more port scans`, margin, yPosition);
      yPosition += 6;
    }

    yPosition += 5;
  }

  // Discovered Subdomains Section
  if (reportData.discovered_subdomains.length > 0) {
    checkPageBreak(50);
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Discovered Subdomains', margin, yPosition);
    yPosition += 10;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);

    reportData.discovered_subdomains.slice(0, 8).forEach((scan, index) => {
      checkPageBreak(25);
      pdf.text(`${index + 1}. ${scan.base_domain} (${scan.total_found} subdomains)`, margin, yPosition);
      yPosition += 5;

      const subdomainsText = scan.discovered_subdomains.slice(0, 3).join(', ');
      pdf.setFontSize(8);
      pdf.text(`   ${subdomainsText}${scan.discovered_subdomains.length > 3 ? '...' : ''}`, margin + 5, yPosition);
      yPosition += 4;

      pdf.setFontSize(9);
      pdf.text(`   Method: ${scan.scan_method} | Status: ${scan.status}`, margin + 5, yPosition);
      yPosition += 6;
    });

    if (reportData.discovered_subdomains.length > 8) {
      pdf.text(`... and ${reportData.discovered_subdomains.length - 8} more subdomain scans`, margin, yPosition);
      yPosition += 6;
    }

    yPosition += 5;
  }

  // Vulnerabilities Section
  if (reportData.vulnerabilities.length > 0) {
    checkPageBreak(60);
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Detected Vulnerabilities', margin, yPosition);
    yPosition += 10;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);

    // Group vulnerabilities by severity
    const groupedVulns = reportData.vulnerabilities.reduce((acc, vuln) => {
      if (!acc[vuln.severity]) acc[vuln.severity] = [];
      acc[vuln.severity].push(vuln);
      return acc;
    }, {} as Record<string, typeof reportData.vulnerabilities>);

    Object.entries(groupedVulns).forEach(([severity, vulns]) => {
      checkPageBreak(30);
      pdf.setFont('helvetica', 'bold');
      pdf.text(`${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity (${vulns.length})`, margin, yPosition);
      yPosition += 6;

      pdf.setFont('helvetica', 'normal');
      vulns.slice(0, 3).forEach((vuln, index) => {
        checkPageBreak(15);
        pdf.text(`• ${vuln.vulnerability_name}`, margin + 5, yPosition);
        yPosition += 4;
        pdf.setFontSize(8);
        pdf.text(`  ${vuln.affected_url} (CVSS: ${vuln.cvss_score})`, margin + 10, yPosition);
        yPosition += 4;
        pdf.setFontSize(9);
      });

      if (vulns.length > 3) {
        pdf.text(`  ... and ${vulns.length - 3} more`, margin + 5, yPosition);
        yPosition += 4;
      }

      yPosition += 3;
    });
  }

  // Recent Scans Section
  if (reportData.recent_scans.length > 0) {
    checkPageBreak(50);
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Recent Security Scans', margin, yPosition);
    yPosition += 10;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);

    reportData.recent_scans.slice(0, 5).forEach((scan, index) => {
      checkPageBreak(20);
      pdf.text(`${index + 1}. ${scan.scanned_url}`, margin, yPosition);
      yPosition += 5;
      pdf.text(`   Mode: ${scan.scan_mode} | Findings: ${scan.findings} | Status: ${scan.status}`, margin + 5, yPosition);
      yPosition += 4;
      pdf.text(`   Date: ${new Date(scan.scan_timestamp).toLocaleDateString()}`, margin + 5, yPosition);
      yPosition += 6;
    });
  }

  // Footer
  const pageCount = pdf.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    pdf.setPage(i);
    pdf.setFontSize(8);
    pdf.setFont('helvetica', 'normal');
    pdf.text(`Unified Security Report - Page ${i} of ${pageCount}`, margin, pageHeight - 10);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, pageWidth - 80, pageHeight - 10);
  }

  // Save the PDF
  const fileName = `unified-security-report-${new Date().toISOString().split('T')[0]}.pdf`;
  pdf.save(fileName);
};

// Generate CSV report
export const generateUnifiedCSVReport = (reportData: UnifiedSecurityReport): void => {
  const csvData: string[] = [];

  // Header
  csvData.push('Unified Security Report');
  csvData.push(`Generated: ${new Date(reportData.scan_timestamp).toLocaleString()}`);
  csvData.push('');

  // Summary
  csvData.push('EXECUTIVE SUMMARY');
  csvData.push(`Total Scans,${reportData.total_scans}`);
  csvData.push(`Last Scan Date,${new Date(reportData.last_scan_date).toLocaleDateString()}`);
  csvData.push(`Critical Vulnerabilities,${reportData.severity_breakdown.critical}`);
  csvData.push(`High Vulnerabilities,${reportData.severity_breakdown.high}`);
  csvData.push(`Medium Vulnerabilities,${reportData.severity_breakdown.medium}`);
  csvData.push(`Low Vulnerabilities,${reportData.severity_breakdown.low}`);
  csvData.push(`Open Ports Detected,${reportData.open_ports.length}`);
  csvData.push(`Subdomains Discovered,${reportData.discovered_subdomains.reduce((sum, scan) => sum + scan.total_found, 0)}`);
  csvData.push(`Total Vulnerabilities,${reportData.vulnerabilities.length}`);
  csvData.push('');

  // Severity Breakdown
  csvData.push('SEVERITY BREAKDOWN');
  csvData.push('Severity,Count');
  csvData.push(`Critical,${reportData.severity_breakdown.critical}`);
  csvData.push(`High,${reportData.severity_breakdown.high}`);
  csvData.push(`Medium,${reportData.severity_breakdown.medium}`);
  csvData.push(`Low,${reportData.severity_breakdown.low}`);
  csvData.push('');

  // Open Ports
  if (reportData.open_ports.length > 0) {
    csvData.push('OPEN PORTS DETECTED');
    csvData.push('Target Host,Open Ports Count,Ports Details,Scan Method,Scan Date');
    reportData.open_ports.forEach(scan => {
      const portsDetails = scan.open_ports.map(p => `${p.port}/${p.protocol}(${p.service})`).join('; ');
      csvData.push(`"${scan.target_host}",${scan.open_count},"${portsDetails}","${scan.scan_method}","${new Date(scan.timestamp).toLocaleDateString()}"`);
    });
    csvData.push('');
  }

  // Discovered Subdomains
  if (reportData.discovered_subdomains.length > 0) {
    csvData.push('DISCOVERED SUBDOMAINS');
    csvData.push('Base Domain,Total Found,Subdomains,Scan Method,Status,Scan Date');
    reportData.discovered_subdomains.forEach(scan => {
      const subdomains = scan.discovered_subdomains.join('; ');
      csvData.push(`"${scan.base_domain}",${scan.total_found},"${subdomains}","${scan.scan_method}","${scan.status}","${new Date(scan.timestamp).toLocaleDateString()}"`);
    });
    csvData.push('');
  }

  // Vulnerabilities
  if (reportData.vulnerabilities.length > 0) {
    csvData.push('DETECTED VULNERABILITIES');
    csvData.push('Vulnerability Name,Severity,Affected URL,CVSS Score,Confidence,Description,Scan Date');
    reportData.vulnerabilities.forEach(vuln => {
      csvData.push(`"${vuln.vulnerability_name}","${vuln.severity}","${vuln.affected_url}",${vuln.cvss_score},${vuln.confidence},"${vuln.description.replace(/"/g, '""')}","${new Date(vuln.timestamp).toLocaleDateString()}"`);
    });
    csvData.push('');
  }

  // Recent Scans
  if (reportData.recent_scans.length > 0) {
    csvData.push('RECENT SECURITY SCANS');
    csvData.push('Scanned URL,Scan Mode,Status,Findings Count,Scan Date');
    reportData.recent_scans.forEach(scan => {
      csvData.push(`"${scan.scanned_url}","${scan.scan_mode}","${scan.status}",${scan.findings},"${new Date(scan.scan_timestamp).toLocaleDateString()}"`);
    });
  }

  // Create and download CSV file
  const csvContent = csvData.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `unified-security-report-${new Date().toISOString().split('T')[0]}.csv`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

// Generate JSON report
export const generateUnifiedJSONReport = (reportData: UnifiedSecurityReport): void => {
  const jsonContent = JSON.stringify(reportData, null, 2);
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `unified-security-report-${new Date().toISOString().split('T')[0]}.json`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

// Main function to generate unified report in specified format
export const generateUnifiedSecurityReport = async (format: 'pdf' | 'csv' | 'json'): Promise<void> => {
  try {
    const reportData = await fetchUnifiedReportData();

    switch (format) {
      case 'pdf':
        await generateUnifiedPDFReport(reportData);
        break;
      case 'csv':
        generateUnifiedCSVReport(reportData);
        break;
      case 'json':
        generateUnifiedJSONReport(reportData);
        break;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  } catch (error) {
    console.error('Error generating unified security report:', error);
    alert(`Failed to generate ${format.toUpperCase()} report. Please check the console for details.`);
  }
};