import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Menu, Search, PlusCircle, Download, Bell, X } from 'lucide-react';
import './Topbar.css';

interface TopbarProps {
  onToggleSidebar?: () => void;
}

export function Topbar({ onToggleSidebar = () => {} }: TopbarProps) {
  const navigate = useNavigate();
  const [showNotifications, setShowNotifications] = useState(false);

  const handleNewScan = () => {
    navigate('/vulnerability-analysis');
  };

  const handleExport = () => {
    // Get current scan data from localStorage or state
    const scanHistory = localStorage.getItem('scanHistory');
    if (scanHistory) {
      const data = JSON.parse(scanHistory);
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-export-${new Date().getTime()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      alert('No scan data available to export');
    }
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // TODO: Implement search functionality
    const query = e.currentTarget.value;
    if (query) {
      // Could filter scans, vulnerabilities, etc. based on query
    }
  };

  return (
    <header className="vc-topbar">
      <div className="vc-top-left">
        <button className="vc-hamburger" onClick={onToggleSidebar} aria-label="Toggle navigation">
          <Menu />
        </button>
        <div className="vc-search">
          <Search />
          <input 
            placeholder="Search scans, targets, or IDs..." 
            onChange={handleSearchChange}
          />
        </div>
      </div>

      <div className="vc-top-right">
        <button className="vc-action" onClick={handleNewScan} title="Start a new scan">
          <PlusCircle />
          <span>New Scan</span>
        </button>
        <button className="vc-action" onClick={handleExport} title="Export scan results">
          <Download />
          <span>Export</span>
        </button>
        <div className="vc-notify-container">
          <button 
            className="vc-notify" 
            onClick={() => setShowNotifications(!showNotifications)}
            title="View notifications"
          >
            <Bell />
          </button>
          {showNotifications && (
            <div className="vc-notifications-panel">
              <div className="vc-notif-header">
                <h4>Notifications</h4>
                <button 
                  className="vc-notif-close"
                  onClick={() => setShowNotifications(false)}
                >
                  <X size={16} />
                </button>
              </div>
              <div className="vc-notif-content">
                <p className="vc-notif-empty">No new notifications</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
