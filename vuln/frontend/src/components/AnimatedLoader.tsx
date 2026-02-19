import React from 'react';
import './AnimatedLoader.css';

interface AnimatedLoaderProps {
  variant?: 'dots' | 'pulse' | 'bars' | 'wave';
  size?: 'small' | 'medium' | 'large';
  message?: string;
}

export const AnimatedLoader: React.FC<AnimatedLoaderProps> = ({
  variant = 'dots',
  size = 'medium',
  message,
}) => {
  const renderLoader = () => {
    switch (variant) {
      case 'pulse':
        return <div className={`loader-pulse loader-pulse--${size}`} />;
      case 'bars':
        return (
          <div className={`loader-bars loader-bars--${size}`}>
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="loader-bar" style={{ animationDelay: `${i * 0.1}s` }} />
            ))}
          </div>
        );
      case 'wave':
        return (
          <div className={`loader-wave loader-wave--${size}`}>
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="wave-item" style={{ animationDelay: `${i * 0.15}s` }} />
            ))}
          </div>
        );
      case 'dots':
      default:
        return (
          <div className={`loader-dots loader-dots--${size}`}>
            <div className="dot" style={{ animationDelay: '0s' }} />
            <div className="dot" style={{ animationDelay: '0.15s' }} />
            <div className="dot" style={{ animationDelay: '0.3s' }} />
          </div>
        );
    }
  };

  return (
    <div className={`animated-loader animated-loader--${size}`}>
      {renderLoader()}
      {message && <p className="loader-message">{message}</p>}
    </div>
  );
};

export default AnimatedLoader;
