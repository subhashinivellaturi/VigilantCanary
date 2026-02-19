import React, { lazy, Suspense } from 'react';
import { NavLink } from 'react-router-dom';
import './Sidebar.css';

const SecurityChatbot = lazy(() => import('./SecurityChatbot').then(m => ({ default: m.SecurityChatbot })));

export function Sidebar() {
  return (
    <aside className="vc-sidebar">
      <div className="vc-brand">
        <div className="vc-logo">VC</div>
        <div className="vc-title">Vigilant Canary</div>
      </div>

      <nav className="vc-nav">
        <NavLink to="/" className="vc-nav-link" end>
          Dashboard
        </NavLink>
        <NavLink to="/recent-scans" className="vc-nav-link">
          Recent Scans
        </NavLink>
        <NavLink to="/scanner" className="vc-nav-link">
          Vulnerability Scanner
        </NavLink>
        <NavLink to="/port-scanner" className="vc-nav-link">
          Port Scanner
        </NavLink>
        <NavLink to="/subdomain-finder" className="vc-nav-link">
          Subdomain Finder
        </NavLink>
        <NavLink to="/dashboard-full" className="vc-nav-link">
          Dashboard (Full)
        </NavLink>
        <NavLink to="/settings" className="vc-nav-link">
          Settings
        </NavLink>
      </nav>

      <div className="vc-chatbot">
        <h4 className="vc-chat-title">Security Assistant</h4>
        <div className="vc-chat-container">
          <Suspense fallback={<div className="vc-chat-loading">Loading assistant…</div>}>
            <SecurityChatbot />
          </Suspense>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  Search,
  Wifi,
  Globe,
  History,
  Settings,
  X,
  ChevronRight,
  Activity
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const menuItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard', description: 'Overview & Analytics' },
  { path: '/scanner', icon: Shield, label: 'Vulnerability Scanner', description: 'Web Security Analysis' },
  { path: '/port-scanner', icon: Wifi, label: 'Port Scanner', description: 'Network Discovery' },
  { path: '/subdomain-finder', icon: Globe, label: 'Subdomain Finder', description: 'Domain Enumeration' },
  { path: '/recent-scans', icon: History, label: 'Scan History', description: 'Results & Reports' },
  { path: '/dashboard-full', icon: Activity, label: 'Full Dashboard', description: 'Full feature interactive dashboard' },
  { path: '/settings', icon: Settings, label: 'Settings', description: 'Configuration' },
];

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const location = useLocation();

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed lg:static inset-y-0 left-0 z-50
        w-80 bg-slate-900/95 backdrop-blur-xl border-r border-slate-700/50
        transform transition-all duration-300 ease-in-out shadow-2xl
        ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        <div className="flex items-center justify-between p-6 border-b border-slate-700/50">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-xl">
              <Shield className="h-8 w-8 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Vigilant Canary</h2>
              <p className="text-sm text-slate-400">Security Suite</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-700/50 transition-all duration-200"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <nav className="mt-8 px-4">
          <div className="mb-6">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 mb-4">
              Navigation
            </h3>
            <ul className="space-y-2">
              {menuItems.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;

                return (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      onClick={onClose}
                      className={`
                        group relative flex items-center space-x-4 px-4 py-4 rounded-xl transition-all duration-200
                        ${isActive
                          ? 'bg-gradient-to-r from-blue-600/20 to-purple-600/20 text-white border border-blue-500/30 shadow-lg shadow-blue-500/10'
                          : 'text-slate-300 hover:bg-slate-800/50 hover:text-white hover:border-slate-600/30 border border-transparent'
                        }
                      `}
                    >
                      <div className={`p-2 rounded-lg transition-all duration-200 ${
                        isActive
                          ? 'bg-blue-500/20 text-blue-300'
                          : 'bg-slate-700/50 text-slate-400 group-hover:bg-slate-600/50 group-hover:text-slate-300'
                      }`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className={`font-semibold transition-colors duration-200 ${
                          isActive ? 'text-white' : 'text-slate-300 group-hover:text-white'
                        }`}>
                          {item.label}
                        </div>
                        <div className={`text-xs transition-colors duration-200 ${
                          isActive ? 'text-blue-200' : 'text-slate-500 group-hover:text-slate-400'
                        }`}>
                          {item.description}
                        </div>
                      </div>
                      <ChevronRight className={`h-4 w-4 transition-all duration-200 ${
                        isActive ? 'text-blue-300 translate-x-1' : 'text-slate-500 group-hover:text-slate-400 group-hover:translate-x-1'
                      }`} />
                      {isActive && (
                        <div className="absolute left-0 top-1/2 transform -translate-y-1/2 w-1 h-8 bg-gradient-to-b from-blue-400 to-purple-400 rounded-r-full"></div>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        </nav>

        <div className="absolute bottom-6 left-4 right-4">
          <div className="bg-gradient-to-br from-slate-800/50 to-slate-700/30 backdrop-blur-sm border border-slate-600/30 rounded-xl p-6">
            <div className="flex items-center space-x-3 mb-4">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <Activity className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-white">System Status</h4>
                <p className="text-xs text-slate-400">All systems operational</p>
              </div>
            </div>
            <div className="space-y-3">
              <button className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-600/30 rounded-lg transition-colors duration-200 hover:text-white">
                Export Report
              </button>
              <button className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-600/30 rounded-lg transition-colors duration-200 hover:text-white">
                Schedule Scan
              </button>
              <button className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-600/30 rounded-lg transition-colors duration-200 hover:text-white">
                API Documentation
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}