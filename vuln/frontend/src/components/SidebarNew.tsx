import React, { lazy, Suspense } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  AlertTriangle,
  History,
  Wifi,
  Globe,
  Settings,
  Activity,
  X,
  ChevronRight,
  ShieldCheck,
  Zap
} from 'lucide-react';
import './Sidebar.css';

const SecurityChatbot = lazy(() => import('./SecurityChatbot').then(m => ({ default: m.SecurityChatbot })));

interface Props {
  isOpen?: boolean;
  onClose?: () => void;
}

const menuItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard', description: 'Overview & Analytics' },
  { path: '/vulnerability-analysis', icon: AlertTriangle, label: 'Vulnerability Analysis', description: 'Payload Testing' },
  { path: '/recent-scans', icon: History, label: 'Scan History', description: 'Results & Reports' },
  { path: '/port-scanner', icon: Wifi, label: 'Port Scanner', description: 'Network Discovery' },
  { path: '/subdomain-finder', icon: Globe, label: 'Subdomain Finder', description: 'Domain Enumeration' },
  { path: '/ai-assistant', icon: Zap, label: 'AI Assistant', description: 'Security Chatbot' },
  { path: '/settings', icon: Settings, label: 'Settings', description: 'Configuration' },
];

export function SidebarNew({ isOpen = true, onClose = () => {} }: Props) {
  const location = useLocation();

  return (
    <aside className={`vc-sidebar app-sidebar ${isOpen ? 'open' : 'closed'}`}>
      <div className="vc-brand p-4 border-b border-slate-700/30">
        <div className="flex items-center gap-3">
          <div className="vc-logo flex items-center justify-center rounded-lg bg-gradient-to-br from-blue-500/10 to-purple-500/10 p-2">
            <ShieldCheck className="text-blue-300" />
          </div>
          <div>
            <div className="vc-title font-bold">Vigilant Canary</div>
            <div className="vc-sub text-sm text-slate-400">Security Suite</div>
          </div>
        </div>
        <button className="mobile-close" onClick={onClose} aria-label="Close sidebar"><X /></button>
      </div>

      <nav className="vc-nav p-4">
        <h4 className="nav-section-title">Navigation</h4>
        <ul className="nav-list">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const active = location.pathname === item.path;
            return (
              <li key={item.path} className={`nav-item ${active ? 'active' : ''}`}>
                <Link to={item.path} onClick={onClose} className="nav-link">
                  <div className="nav-icon"><Icon /></div>
                  <div className="nav-text">
                    <div className="nav-label">{item.label}</div>
                    <div className="nav-desc">{item.description}</div>
                  </div>
                  <ChevronRight className="nav-chevron" />
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="vc-bottom p-4 border-t border-slate-700/30">
        <div className="status-card mb-4">
          <div className="status-left">
            <Activity className="status-icon" />
            <div>
              <div className="status-title">System Status</div>
              <div className="status-sub">Operational</div>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}

export default SidebarNew;
