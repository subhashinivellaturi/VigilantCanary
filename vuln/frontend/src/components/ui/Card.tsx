import React from 'react';
import { motion } from 'framer-motion';

type MotionArticleProps = React.ComponentPropsWithoutRef<typeof motion.article>;

interface CardProps extends Omit<MotionArticleProps, 'title' | 'subtitle' | 'children'> {
  title?: string;
  subtitle?: string;
  children?: React.ReactNode;
}

export function Card({ title, subtitle, children, className = '', ...rest }: CardProps) {
  return (
    <motion.article
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ translateY: -4, boxShadow: '0 8px 30px rgba(2,6,23,0.6)' }}
      transition={{ type: 'spring', stiffness: 260, damping: 20 }}
      className={`bg-slate-800/60 border border-slate-700/40 rounded-2xl p-6 shadow-sm ${className}`}
      {...rest}
    >
      {title && (
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-lg font-semibold text-white">{title}</h3>
            {subtitle && <p className="text-sm text-slate-400">{subtitle}</p>}
          </div>
        </div>
      )}

      <div className="flex-1 min-h-0">{children}</div>

    </motion.article>
  );
}
