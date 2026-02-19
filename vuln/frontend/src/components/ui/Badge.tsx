import React from 'react';
import './Badge.css';

interface BadgeProps {
  variant?: 'success' | 'danger' | 'warning' | 'info' | 'default';
  size?: 'sm' | 'md';
  children: React.ReactNode;
  className?: string;
}

export function Badge({ variant = 'default', size = 'md', children, className = '' }: BadgeProps) {
  return (
    <span className={`vc-badge vc-badge--${variant} vc-badge--${size} ${className}`}>
      {children}
    </span>
  );
}

export default Badge;
