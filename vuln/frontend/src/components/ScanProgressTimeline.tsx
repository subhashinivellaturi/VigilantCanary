import React from 'react';
import { Check, Clock, Zap } from 'lucide-react';
import './ScanProgressTimeline.css';

interface TimelineStep {
  id: string;
  label: string;
  status: 'pending' | 'in-progress' | 'complete' | 'error';
  timestamp?: string;
  details?: string;
}

interface ScanProgressTimelineProps {
  steps: TimelineStep[];
  currentStep?: string;
}

export const ScanProgressTimeline: React.FC<ScanProgressTimelineProps> = ({
  steps,
  currentStep,
}) => {
  return (
    <div className="timeline-container">
      {steps.map((step, index) => {
        const isComplete = step.status === 'complete';
        const isInProgress = step.status === 'in-progress';
        const isError = step.status === 'error';
        const isPending = step.status === 'pending';

        return (
          <div key={step.id} className="timeline-item">
            {/* Timeline connector line */}
            {index < steps.length - 1 && (
              <div
                className={`timeline-connector ${
                  isComplete ? 'timeline-connector--complete' : ''
                } ${isInProgress ? 'timeline-connector--active' : ''}`}
              />
            )}

            {/* Step indicator */}
            <div
              className={`timeline-step timeline-step--${step.status}`}
            >
              {isComplete && <Check size={16} />}
              {isInProgress && <Zap size={16} />}
              {isPending && <Clock size={16} />}
              {isError && <span>✕</span>}
            </div>

            {/* Step content */}
            <div className="timeline-content">
              <div className="timeline-label">{step.label}</div>
              {step.details && (
                <div className="timeline-details">{step.details}</div>
              )}
              {step.timestamp && (
                <div className="timeline-timestamp">{step.timestamp}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default ScanProgressTimeline;
