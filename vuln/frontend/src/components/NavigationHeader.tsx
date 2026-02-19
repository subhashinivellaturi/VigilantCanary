import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Menu, 
  Bell, 
  User, 
  Zap, 
  Settings, 
  Shield,
  Search,
  // LogOut,  // Not in lucide-react
  HelpCircle,
  ChevronDown,
  Globe,
  // Moon,  // Not in lucide-react
  // Sun,  // Not in lucide-react
  Activity,
  AlertTriangle,
  // CheckCircle2,  // not in lucide-react, use CheckCircle
  CheckCircle
} from 'lucide-react';
import './NavigationHeader.css';

interface HeaderProps {
  onMenuClick: () => void;
  darkMode?: boolean;
  onThemeToggle?: () => void;
}

interface Notification {
  id: number;
  title: string;
  message: string;
  time: string;
  type: 'alert' | 'scan' | 'system' | 'info';
  read: boolean;
}

export function NavigationHeader({ onMenuClick, darkMode = true, onThemeToggle }: HeaderProps) {
  const [searchOpen, setSearchOpen] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [notifications] = useState<Notification[]>([
    { id: 1, title: 'Critical Alert', message: 'SQL Injection detected on API endpoint', time: '2 min ago', type: 'alert', read: false },
    { id: 2, title: 'Scan Complete', message: 'Port scan completed for 192.168.1.1', time: '15 min ago', type: 'scan', read: true },
    { id: 3, title: 'System Update', message: 'Security rules database updated', time: '1 hour ago', type: 'system', read: true },
    { id: 4, title: 'New Feature', message: 'Subdomain enumeration tool now available', time: '3 hours ago', type: 'info', read: true },
  ]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const handleQuickScan = () => {
    setScanning(true);
    // Simulate scan completion
    setTimeout(() => {
      setScanning(false);
    }, 3000);
  };

  const markAllAsRead = () => {
    // Implementation would update notifications
    setShowNotifications(false);
  };

  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'alert': return <AlertTriangle className="h-4 w-4" />;
      case 'scan': return <Activity className="h-4 w-4" />;
      case 'system': return <Shield className="h-4 w-4" />;
      case 'info': return <CheckCircle className="h-4 w-4" />;
      default: return <Bell className="h-4 w-4" />;
    }
  };

  return (
    <header className="navigation-header">
      {/* Background Glow Effect */}
      <div className="header-glow" />
      
      <div className="header-container">
        {/* Left Section */}
        <div className="header-left">
          <motion.button
            onClick={onMenuClick}
            className="menu-toggle"
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
          >
            <Menu className="menu-icon" />
          </motion.button>

          <div className="brand-container">
            <motion.div 
              className="brand-logo"
              whileHover={{ rotate: 5 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <div className="logo-glow" />
              <Shield className="logo-icon" />
            </motion.div>
            <div className="brand-text">
              <h1 className="brand-title">Vigilant Canary</h1>
              <p className="brand-subtitle">AI-Powered Security Intelligence Platform</p>
            </div>
          </div>
        </div>

        {/* Center Section - Search */}
        <div className="header-center">
          <div className={`search-container ${searchOpen ? 'expanded' : ''}`}>
            <motion.button
              className="search-toggle"
              onClick={() => setSearchOpen(!searchOpen)}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
            >
              <Search className="search-icon" />
            </motion.button>
            <AnimatePresence>
              {searchOpen && (
                <motion.div
                  className="search-input-wrapper"
                  initial={{ width: 0, opacity: 0 }}
                  animate={{ width: 300, opacity: 1 }}
                  exit={{ width: 0, opacity: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  <input
                    type="text"
                    className="search-input"
                    placeholder="Search endpoints, scans, reports..."
                    autoFocus
                  />
                  <span className="search-hint">Press ⌘K to search</span>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Right Section */}
        <div className="header-right">
          {/* Quick Scan Button */}
          <motion.button
            className="quick-scan-btn"
            onClick={handleQuickScan}
            disabled={scanning}
            whileHover={{ scale: 1.05, y: -2 }}
            whileTap={{ scale: 0.95 }}
            animate={scanning ? {
              boxShadow: [
                "0 0 0 0 rgba(59, 130, 246, 0)",
                "0 0 0 10px rgba(59, 130, 246, 0.4)",
                "0 0 0 0 rgba(59, 130, 246, 0)"
              ]
            } : {}}
            transition={scanning ? {
              boxShadow: {
                duration: 1.5,
                repeat: Infinity,
                ease: "easeInOut"
              }
            } : {}}
          >
            <div className="scan-btn-content">
              {scanning ? (
                <>
                  <div className="scanning-spinner" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Zap className="scan-icon" />
                  <span>Quick Scan</span>
                </>
              )}
            </div>
            <div className="scan-pulse" />
          </motion.button>

          {/* Theme Toggle */}
          <motion.button
            className="theme-toggle"
            onClick={onThemeToggle}
            whileHover={{ scale: 1.1, rotate: 15 }}
            whileTap={{ scale: 0.95 }}
          >
            {darkMode ? <Zap className="theme-icon" /> : <Zap className="theme-icon" />}
          </motion.button>

          {/* Language/Region */}
          <button className="locale-btn">
            <Globe className="locale-icon" />
            <span className="locale-text">EN</span>
          </button>

          {/* Notifications */}
          <div className="notification-container">
            <motion.button
              className="notification-btn"
              onClick={() => setShowNotifications(!showNotifications)}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
              animate={unreadCount > 0 ? {
                rotate: [0, -10, 10, -10, 0],
                transition: { duration: 0.5 }
              } : {}}
            >
              <Bell className="notification-icon" />
              {unreadCount > 0 && (
                <motion.span
                  className="notification-badge"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: "spring" }}
                >
                  {unreadCount}
                </motion.span>
              )}
            </motion.button>

            {/* Notification Dropdown */}
            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  className="notification-dropdown"
                  initial={{ opacity: 0, y: -20, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -20, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="notification-header">
                    <h3>Notifications</h3>
                    <button className="mark-read-btn" onClick={markAllAsRead}>
                      Mark all as read
                    </button>
                  </div>
                  <div className="notification-list">
                    {notifications.map((notification) => (
                      <div
                        key={notification.id}
                        className={`notification-item ${notification.read ? 'read' : 'unread'}`}
                      >
                        <div className="notification-icon-wrapper">
                          {getNotificationIcon(notification.type)}
                        </div>
                        <div className="notification-content">
                          <div className="notification-title">
                            {notification.title}
                            {!notification.read && <div className="unread-dot" />}
                          </div>
                          <div className="notification-message">{notification.message}</div>
                          <div className="notification-time">{notification.time}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <button className="view-all-btn">View all notifications</button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* User Profile */}
          <div className="user-profile-container">
            <motion.button
              className="user-profile-btn"
              onClick={() => setShowUserMenu(!showUserMenu)}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <div className="user-avatar">
                <User className="user-icon" />
                <div className="online-status" />
              </div>
              <div className="user-info">
                <span className="user-name">Security Admin</span>
                <span className="user-role">Administrator</span>
              </div>
              <ChevronDown className="dropdown-icon" />
            </motion.button>

            {/* User Menu Dropdown */}
            <AnimatePresence>
              {showUserMenu && (
                <motion.div
                  className="user-menu-dropdown"
                  initial={{ opacity: 0, y: -20, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -20, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="user-menu-header">
                    <div className="menu-user-avatar">
                      <User className="menu-user-icon" />
                    </div>
                    <div>
                      <div className="menu-user-name">Security Admin</div>
                      <div className="menu-user-email">admin@vigilantcanary.com</div>
                    </div>
                  </div>
                  <div className="user-menu-items">
                    <button className="menu-item">
                      <User className="menu-item-icon" />
                      <span>Profile Settings</span>
                    </button>
                    <button className="menu-item">
                      <Settings className="menu-item-icon" />
                      <span>Dashboard Settings</span>
                    </button>
                    <button className="menu-item">
                      <HelpCircle className="menu-item-icon" />
                      <span>Help & Support</span>
                    </button>
                    <div className="menu-divider" />
                    <button className="menu-item logout">
                      {/* <LogOut className="menu-item-icon" /> */}
                      <span>Sign Out</span>
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* System Status Bar */}
      <div className="system-status-bar">
        <div className="status-item">
          <div className="status-dot active" />
          <span>API: Operational</span>
        </div>
        <div className="status-item">
          <div className="status-dot active" />
          <span>Scanner: Active</span>
        </div>
        <div className="status-item">
          <div className="status-dot warning" />
          <span>Database: Syncing</span>
        </div>
        <div className="status-item">
          <div className="status-dot active" />
          <span>AI Model: Live</span>
        </div>
      </div>
    </header>
  );
}