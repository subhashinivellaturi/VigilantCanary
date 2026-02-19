import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger';
}

/**
 * Button
 * @param variant - visual variant
 */
export const Button: React.FC<ButtonProps> = ({ variant = 'primary', className = '', children, ...rest }) => {
  const base = 'inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2';
  const variants: Record<string, string> = {
    primary: `${base} bg-emerald-600 hover:bg-emerald-500 text-white focus:ring-emerald-400`,
    ghost: `${base} bg-transparent border border-slate-700 text-white hover:bg-slate-800`,
    danger: `${base} bg-red-600 hover:bg-red-500 text-white focus:ring-red-400`,
  };

  return (
    <button className={`${variants[variant]} ${className}`} {...rest}>
      {children}
    </button>
  );
};
