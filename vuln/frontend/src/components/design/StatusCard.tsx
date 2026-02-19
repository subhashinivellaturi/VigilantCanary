import React from 'react';
import { Card } from '../ui/Card';

export interface StatusCardProps {
  label: string;
  value: string | number;
  variant?: 'normal' | 'muted';
}

/**
 * StatusCard
 */
export const StatusCard: React.FC<StatusCardProps> = ({ label, value, variant = 'normal' }) => {
  return (
    <Card className={`p-4 ${variant === 'muted' ? 'opacity-80' : ''}`}>
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-400">{label}</div>
        <div className="text-xl font-semibold">{value}</div>
      </div>
    </Card>
  );
};
