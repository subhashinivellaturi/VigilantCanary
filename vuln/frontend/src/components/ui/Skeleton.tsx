import React from 'react';
import './Skeleton.css';

interface SkeletonProps {
  count?: number;
  height?: string;
  width?: string;
  circle?: boolean;
  className?: string;
}

export function Skeleton({ count = 1, height = '20px', width = '100%', circle = false, className = '' }: SkeletonProps) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className={`vc-skeleton ${circle ? 'vc-skeleton--circle' : ''} ${className}`}
          style={{
            height: circle ? width : height,
            width,
            borderRadius: circle ? '50%' : '8px',
            marginBottom: i < count - 1 ? '12px' : '0',
          }}
        />
      ))}
    </>
  );
}

export default Skeleton;
