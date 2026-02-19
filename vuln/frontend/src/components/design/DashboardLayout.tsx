import React from 'react';
import { Card } from '../ui/Card';
import { Navigation } from './Navigation';

export interface DashboardLayoutProps {
  children: React.ReactNode;
}

/**
 * Dashboard layout with responsive sidebar and content area
 */
export const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-950 text-white">
      <Navigation />

      <main className="p-6 md:p-8 lg:p-12 max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <aside className="lg:col-span-1">
            <Card title="System Status" className="mb-6">
              {/* Placeholder for quick status */}
              <div className="text-sm text-slate-300">Availability: <span className="font-semibold">99.99%</span></div>
            </Card>

            <Card title="Quick Actions">
              <div className="space-y-2">
                <button className="w-full p-2 rounded-md bg-emerald-600 hover:bg-emerald-500">Run Scan</button>
                <button className="w-full p-2 rounded-md bg-slate-800 hover:bg-slate-700">Export Report</button>
              </div>
            </Card>
          </aside>

          <section className="lg:col-span-3 space-y-6">
            {children}
          </section>
        </div>
      </main>
    </div>
  );
};
