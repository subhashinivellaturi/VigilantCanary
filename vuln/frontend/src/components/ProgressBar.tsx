import React from 'react';
import './ProgressBar.css';

interface ProgressBarProps {
  progress: number; // 0-100
  status?: 'scanning' | 'analyzing' | 'complete' | 'error';
  label?: string;
  showPercentage?: boolean;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  progress,
  status = 'scanning',
  label,
  showPercentage = true,
}) => {
  return (
    <div className="progress-container">
      {label && <div className="progress-label">{label}</div>}
      <div className={`progress-bar progress-bar--${status}`}>
        <div
          className="progress-bar__fill"
          style={{ width: `${Math.min(progress, 100)}%` }}
        />
      </div>
      {showPercentage && (
        <div className="progress-percentage">
          {Math.round(Math.min(progress, 100))}%
        </div>
      )}
    </div>
  );
};

export default ProgressBar;
