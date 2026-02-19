import React from 'react';
import './SkeletonLoader.css';

interface SkeletonLoaderProps {
  width?: string | number;
  height?: string | number;
  variant?: 'text' | 'line' | 'block' | 'circle';
  count?: number;
  className?: string;
}

export const SkeletonLoader: React.FC<SkeletonLoaderProps> = ({
  width = '100%',
  height = '20px',
  variant = 'line',
  count = 1,
  className = '',
}) => {
  const skeletons = Array.from({ length: count });

  const getSkeletonStyle = () => {
    const baseStyle: React.CSSProperties = {
      width: typeof width === 'number' ? `${width}px` : width,
      height: typeof height === 'number' ? `${height}px` : height,
    };

    switch (variant) {
      case 'circle':
        return { ...baseStyle, borderRadius: '50%' };
      case 'block':
        return { ...baseStyle, borderRadius: '8px' };
      default:
        return { ...baseStyle, borderRadius: '4px' };
    }
  };

  return (
    <>
      {skeletons.map((_, idx) => (
        <div
          key={idx}
          className={`skeleton-loader ${variant} ${className}`}
          style={{
            ...getSkeletonStyle(),
            marginBottom: idx < skeletons.length - 1 ? '12px' : '0',
          }}
        />
      ))}
    </>
  );
};

interface ResultSkeletonProps {
  lines?: number;
}

export const ResultSkeleton: React.FC<ResultSkeletonProps> = ({ lines = 5 }) => (
  <div className="result-skeleton">
    <SkeletonLoader height="16px" width="60%" />
    <SkeletonLoader height="14px" width="100%" count={lines} />
  </div>
);

export default SkeletonLoader;
