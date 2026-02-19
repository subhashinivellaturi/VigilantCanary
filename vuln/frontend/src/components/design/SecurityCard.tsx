import React from 'react';
import { Card } from '../ui/Card';

export interface SecurityCardProps {
  title?: string;
  subtitle?: string;
  children?: React.ReactNode;
  className?: string;
}

/**
 * SecurityCard
 */
export const SecurityCard: React.FC<SecurityCardProps> = ({ title, subtitle, children, className = 'p-4' }) => {
  return (
    <Card title={title} subtitle={subtitle} className={className}>
      <div className="space-y-3">{children}</div>
    </Card>
  );
};
