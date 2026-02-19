import React from 'react';
import { StatusCard } from './StatusCard';

/**
 * SystemStatus - group of status indicators
 */
export const SystemStatus: React.FC = () => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <StatusCard label="Uptime" value="99.99%" />
      <StatusCard label="Active Scans" value={3} />
      <StatusCard label="Open Findings" value={12} variant="muted" />
    </div>
  );
};
