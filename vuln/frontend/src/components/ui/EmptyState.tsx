import React from 'react';
import './EmptyState.css';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="vc-empty-state">
      {icon && <div className="vc-empty-state__icon">{icon}</div>}
      <h3 className="vc-empty-state__title">{title}</h3>
      {description && <p className="vc-empty-state__description">{description}</p>}
      {action && (
        <button 
          className="vc-empty-state__button"
          onClick={action.onClick}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

export default EmptyState;
