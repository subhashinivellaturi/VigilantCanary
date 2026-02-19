import React, { useState } from 'react';
import { Menu } from 'lucide-react';

export const Navigation: React.FC = () => {
  const [open, setOpen] = useState(false);

  return (
    <header className="w-full border-b border-slate-700/30 bg-slate-900/40 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button aria-label="Toggle menu" onClick={() => setOpen((s) => !s)} className="p-2 rounded-md hover:bg-slate-800">
            <Menu className="w-5 h-5" />
          </button>
          <div className="text-xl font-semibold">Vigilant Canary</div>
        </div>

        <nav className="hidden md:flex items-center gap-4">
          <a className="text-slate-300 hover:text-white" href="#">Dashboard</a>
          <a className="text-slate-300 hover:text-white" href="#">Scans</a>
          <a className="text-slate-300 hover:text-white" href="#">Settings</a>
        </nav>

        <div className="flex items-center gap-3">
          <button className="px-3 py-1 rounded-md border border-slate-700">Profile</button>
        </div>
      </div>

      {/* Mobile drawer */}
      {open && (
        <div className="md:hidden border-t border-slate-700/30 bg-slate-900/60">
          <div className="px-4 py-3 space-y-2">
            <a className="block text-slate-300" href="#">Dashboard</a>
            <a className="block text-slate-300" href="#">Scans</a>
            <a className="block text-slate-300" href="#">Settings</a>
          </div>
        </div>
      )}
    </header>
  );
};
