import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';
import './Breadcrumb.css';

const pathLabels: Record<string, string> = {
  '/': 'Dashboard',
  '/scanner': 'Vulnerability Scanner',
  '/port-scanner': 'Port Scanner',
  '/subdomain-finder': 'Subdomain Finder',
  '/recent-scans': 'Scan History',
  '/settings': 'Settings',
};

export function Breadcrumb() {
  const location = useLocation();

  // If on root, don't show breadcrumbs (redundant with navbar)
  if (location.pathname === '/') {
    return null;
  }

  const currentLabel = pathLabels[location.pathname] || location.pathname;

  return (
    <nav className="vc-breadcrumb" aria-label="Breadcrumb">
      <div className="breadcrumb-item">
        <Link to="/" className="breadcrumb-link">
          <Home size={16} />
          <span>Dashboard</span>
        </Link>
        <ChevronRight className="breadcrumb-sep" size={16} />
      </div>
      <div className="breadcrumb-item">
        <span className="breadcrumb-current">{currentLabel}</span>
      </div>
    </nav>
  );
}

export default Breadcrumb;
