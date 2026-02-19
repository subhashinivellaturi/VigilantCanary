import { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, useLocation } from "react-router-dom";
import { DashboardEnhanced } from "./components/DashboardEnhanced";
import { DashboardFull } from "./components/DashboardFull";
import { VulnerabilityAnalysis } from "./components/VulnerabilityAnalysis";
import { VulnerabilityScanner } from "./components/VulnerabilityScanner";
import { PortScanner } from "./components/PortScannerNew";
import { SubdomainFinder } from "./components/SubdomainFinderNew";
import { RecentScans } from "./components/RecentScans";
import { Settings } from "./components/Settings";
import { PageTransition } from "./components/ui/PageTransition";
import { ToastProvider } from "./components/ui/Toast";
import { AIAssistant } from "./components/AIAssistant";
import { fetchHealth } from "./api/client";
import type { HealthStatus } from "./types";
import SidebarNew from "./components/SidebarNew";
import { Topbar } from "./components/Topbar";
import Breadcrumb from "./components/Breadcrumb";
import Footer from "./components/Footer";
import "./styles.css";

function AppShellContent() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  return (
    <div style={{ display: 'flex', minHeight: '100vh', flexDirection: 'row' }}>
      <SidebarNew isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <Topbar onToggleSidebar={() => setSidebarOpen((s) => !s)} />

        <div style={{ flex: 1, padding: location.pathname === '/ai-assistant' ? '0' : '16px 24px', overflowY: 'auto' }}>
          {location.pathname !== '/ai-assistant' && <Breadcrumb />}

          <PageTransition>
            <Routes>
              <Route path="/" element={<DashboardEnhanced />} />
              <Route path="/vulnerability-analysis" element={<VulnerabilityAnalysis />} />
              <Route path="/scanner" element={<VulnerabilityScanner />} />
              <Route path="/port-scanner" element={<PortScanner />} />
              <Route path="/subdomain-finder" element={<SubdomainFinder />} />
              <Route path="/ai-assistant" element={<AIAssistant />} />
              <Route path="/recent-scans" element={<RecentScans />} />
              <Route path="/dashboard-full" element={<DashboardFull />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </PageTransition>
        </div>

        {location.pathname !== '/ai-assistant' && <Footer />}
      </main>

      {/* Floating AI Assistant button (only on non-AI-page routes) */}
      {location.pathname !== '/ai-assistant' && <AIAssistant />}
    </div>
  );
}

function AppShell() {
  return (
    <Router>
      <ToastProvider>
        <AppShellContent />
      </ToastProvider>
    </Router>
  );
}

export default AppShell;
