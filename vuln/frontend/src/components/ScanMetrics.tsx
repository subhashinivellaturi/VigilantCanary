import React, { useEffect, useState } from 'react';
import './ScanMetrics.css';

interface MetricItem {
  label: string;
  value: number;
  unit?: string;
  icon?: React.ReactNode;
}

interface ScanMetricsProps {
  isScanning: boolean;
  metrics?: MetricItem[];
}

export const ScanMetrics: React.FC<ScanMetricsProps> = ({ 
  isScanning,
  metrics = [
    { label: 'URLs Scanned', value: 0, unit: '' },
    { label: 'Issues Found', value: 0, unit: '' },
    { label: 'Time Elapsed', value: 0, unit: 's' },
    { label: 'Requests Sent', value: 0, unit: '' },
  ]
}) => {
  const [animatedMetrics, setAnimatedMetrics] = useState(metrics);
  const [elapsedTime, setElapsedTime] = useState(0);

  // Simulate metric increments during scan
  useEffect(() => {
    if (!isScanning) return;

    const timer = setInterval(() => {
      setElapsedTime((prev) => prev + 1);
      setAnimatedMetrics((prev) =>
        prev.map((metric) => {
          if (metric.label === 'Time Elapsed') {
            return { ...metric, value: elapsedTime };
          }
          if (metric.label === 'URLs Scanned' && Math.random() > 0.7) {
            return { ...metric, value: metric.value + 1 };
          }
          if (metric.label === 'Requests Sent') {
            return { ...metric, value: metric.value + Math.floor(Math.random() * 3) };
          }
          return metric;
        })
      );
    }, 1000);

    return () => clearInterval(timer);
  }, [isScanning, elapsedTime]);

  return (
    <div className={`scan-metrics ${isScanning ? 'scan-metrics--active' : ''}`}>
      {animatedMetrics.map((metric, idx) => (
        <div key={idx} className="metric-item">
          <div className="metric-label">{metric.label}</div>
          <div className={`metric-value ${isScanning ? 'metric-value--animating' : ''}`}>
            {metric.value}
            {metric.unit && <span className="metric-unit">{metric.unit}</span>}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ScanMetrics;
