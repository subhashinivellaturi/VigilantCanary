import { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { DashboardEnhanced } from "./components/DashboardEnhanced";
import { DashboardFull } from "./components/DashboardFull";
import { VulnerabilityScanner } from "./components/VulnerabilityScanner";
import { PortScanner } from "./components/PortScanner";
import { SubdomainFinder } from "./components/SubdomainFinder";
import { RecentScans } from "./components/RecentScans";
import { Settings } from "./components/Settings";
import { PageTransition } from "./components/ui/PageTransition";
import { ToastProvider } from "./components/ui/Toast";
import { fetchHealth } from "./api/client";
import type { HealthStatus } from "./types";
import Sidebar from "./components/Sidebar";

function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch((err) => {
        console.warn("Backend unavailable. Make sure backend server is running on port 8007.");
        setHealth(null);
      });
  }, []);

  return (
    <Router>
      <ToastProvider>
        <div style={{ display: 'flex', minHeight: '100vh' }}>
          <Sidebar />
          <main style={{ flex: 1 }}>
            <PageTransition>
              <Routes>
                <Route path="/" element={<DashboardEnhanced />} />
                <Route path="/scanner" element={<VulnerabilityScanner />} />
                <Route path="/port-scanner" element={<PortScanner />} />
                <Route path="/subdomain-finder" element={<SubdomainFinder />} />
                <Route path="/recent-scans" element={<RecentScans />} />
                <Route path="/dashboard-full" element={<DashboardFull />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </PageTransition>
          </main>
        </div>
      </ToastProvider>
    </Router>
  );
}

export default App;
