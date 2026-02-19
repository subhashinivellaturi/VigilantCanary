import React, { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  Key,
  Save,
  AlertCircle,
  ChevronRight,
  Clock
} from 'lucide-react';
import { useToast } from './ui/Toast';
import './Settings.css';

export function Settings() {
  const { showToast } = useToast();
  const [settings, setSettings] = useState({
    security: {
      autoScan: false,
      scanFrequency: 'daily',
      maxConcurrentScans: 3,
      timeoutMinutes: 30
    },
    api: {
      apiKey: '',
      rateLimit: 100,
      allowPublicAccess: false
    }
  });

  const [dirty, setDirty] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showApiKey, setShowApiKey] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem('appSettings');
      if (stored) {
        const parsed = JSON.parse(stored);
        setSettings({
          security: parsed.security || settings.security,
          api: parsed.api || settings.api
        });
        setDirty(false);
      }
    } catch (e) {
      // ignore parse errors
    }
  }, []);

  const handleSettingChange = (category: string, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category as keyof typeof prev],
        [key]: value
      }
    }));
    setDirty(true);
    setErrors((e) => {
      const copy = { ...e };
      delete copy[`${category}.${key}`];
      return copy;
    });
  };

  const validateSettings = () => {
    const errs: Record<string, string> = {};
    if (settings.api.allowPublicAccess && !settings.api.apiKey.trim()) {
      errs['api.apiKey'] = 'API key is required when public access is enabled.';
    }

    if (!Number.isInteger(settings.api.rateLimit) || settings.api.rateLimit < 10 || settings.api.rateLimit > 1000) {
      errs['api.rateLimit'] = 'Rate limit must be between 10 and 1000.';
    }

    if (!Number.isInteger(settings.security.maxConcurrentScans) || settings.security.maxConcurrentScans < 1 || settings.security.maxConcurrentScans > 10) {
      errs['security.maxConcurrentScans'] = 'Max concurrent scans must be between 1 and 10.';
    }

    if (!Number.isInteger(settings.security.timeoutMinutes) || settings.security.timeoutMinutes < 5 || settings.security.timeoutMinutes > 120) {
      errs['security.timeoutMinutes'] = 'Timeout must be between 5 and 120 minutes.';
    }

    return errs;
  };

  const saveSettings = () => {
    const validation = validateSettings();
    if (Object.keys(validation).length > 0) {
      setErrors(validation);
      showToast('Please fix validation errors before saving', 'error');
      return;
    }

    try {
      localStorage.setItem('appSettings', JSON.stringify(settings));
      setDirty(false);
      showToast('Settings saved successfully', 'success');
    } catch (e) {
      console.warn('Failed to save settings', e);
      showToast('Failed to save settings', 'error');
    }
  };

  return (
    <div className="settings-page">
      {/* Header */}
      <div className="settings-header">
        <div className="header-content">
          <h1>Settings</h1>
          <p>Manage your application preferences and configurations</p>
        </div>
        <button
          onClick={saveSettings}
          disabled={!dirty}
          className={`save-btn ${!dirty ? 'disabled' : ''}`}
          title={dirty ? 'Save changes' : 'All changes saved'}
        >
          <Save size={18} />
          {dirty ? 'Save Changes' : 'Saved'}
        </button>
      </div>

      {/* Settings Grid */}
      <div className="settings-grid">
        {/* Scan Settings Card */}
        <div className="settings-card">
          <div className="card-icon">
            <Shield size={24} />
          </div>
          <h2 className="card-title">Scan Settings</h2>
          <p className="card-description">Configure how security scans are executed</p>

          <div className="settings-group">
            {/* Auto Scan Toggle */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Auto Scan</label>
                <p className="setting-hint">Automatically run scans on a schedule</p>
              </div>
              <div className="toggle-switch">
                <input
                  type="checkbox"
                  id="auto-scan"
                  checked={settings.security.autoScan}
                  onChange={(e) => handleSettingChange('security', 'autoScan', e.target.checked)}
                  className="toggle-input"
                />
                <label htmlFor="auto-scan" className="toggle-label"></label>
              </div>
            </div>

            {/* Scan Frequency */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Scan Frequency</label>
                <p className="setting-hint">How often to run automatic scans</p>
              </div>
              <select
                value={settings.security.scanFrequency}
                onChange={(e) => handleSettingChange('security', 'scanFrequency', e.target.value)}
                className="select-control"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>

            {/* Max Concurrent Scans */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Max Concurrent Scans</label>
                <p className="setting-hint">Number of parallel scans allowed</p>
              </div>
              <div className="input-group">
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={settings.security.maxConcurrentScans}
                  onChange={(e) => handleSettingChange('security', 'maxConcurrentScans', parseInt(e.target.value || '0'))}
                  className="number-input"
                  aria-invalid={!!errors['security.maxConcurrentScans']}
                />
              </div>
            </div>
            {errors['security.maxConcurrentScans'] && (
              <div className="error-message">
                <AlertCircle size={16} />
                {errors['security.maxConcurrentScans']}
              </div>
            )}

            {/* Scan Timeout */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Scan Timeout</label>
                <p className="setting-hint">Maximum time for each scan in minutes</p>
              </div>
              <div className="input-group">
                <input
                  type="number"
                  min="5"
                  max="120"
                  value={settings.security.timeoutMinutes}
                  onChange={(e) => handleSettingChange('security', 'timeoutMinutes', parseInt(e.target.value || '0'))}
                  className="number-input"
                  aria-invalid={!!errors['security.timeoutMinutes']}
                />
                <span className="input-suffix">minutes</span>
              </div>
            </div>
            {errors['security.timeoutMinutes'] && (
              <div className="error-message">
                <AlertCircle size={16} />
                {errors['security.timeoutMinutes']}
              </div>
            )}
          </div>
        </div>

        {/* API Settings Card */}
        <div className="settings-card">
          <div className="card-icon api-icon">
            <Key size={24} />
          </div>
          <h2 className="card-title">API Configuration</h2>
          <p className="card-description">Manage API keys and access settings</p>

          <div className="settings-group">
            {/* API Key */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">API Key</label>
                <p className="setting-hint">Your secret API authentication key</p>
              </div>
              <div className="input-group">
                <input
                  type={showApiKey ? 'text' : 'password'}
                  value={settings.api.apiKey}
                  onChange={(e) => handleSettingChange('api', 'apiKey', e.target.value)}
                  placeholder="••••••••••••••••"
                  className="api-input"
                  aria-invalid={!!errors['api.apiKey']}
                />
                <button
                  type="button"
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="show-btn"
                  title={showApiKey ? 'Hide' : 'Show'}
                >
                  {showApiKey ? '🙈' : '👁'}
                </button>
              </div>
            </div>
            {errors['api.apiKey'] && (
              <div className="error-message">
                <AlertCircle size={16} />
                {errors['api.apiKey']}
              </div>
            )}

            {/* Rate Limit */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Rate Limit</label>
                <p className="setting-hint">API requests per minute</p>
              </div>
              <div className="input-group">
                <input
                  type="number"
                  min="10"
                  max="1000"
                  value={settings.api.rateLimit}
                  onChange={(e) => handleSettingChange('api', 'rateLimit', parseInt(e.target.value || '0'))}
                  className="number-input"
                  aria-invalid={!!errors['api.rateLimit']}
                />
                <span className="input-suffix">req/min</span>
              </div>
            </div>
            {errors['api.rateLimit'] && (
              <div className="error-message">
                <AlertCircle size={16} />
                {errors['api.rateLimit']}
              </div>
            )}

            {/* Public Access Toggle */}
            <div className="setting-row">
              <div className="setting-info">
                <label className="setting-name">Public API Access</label>
                <p className="setting-hint">Allow external applications to use your API</p>
              </div>
              <div className="toggle-switch">
                <input
                  type="checkbox"
                  id="public-access"
                  checked={settings.api.allowPublicAccess}
                  onChange={(e) => handleSettingChange('api', 'allowPublicAccess', e.target.checked)}
                  className="toggle-input"
                />
                <label htmlFor="public-access" className="toggle-label"></label>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Settings;