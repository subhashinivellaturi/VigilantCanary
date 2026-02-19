import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { DashboardFull } from '../DashboardFull';
import { ToastProvider } from '../ui/Toast';

global.fetch = vi.fn();

describe('DashboardFull', () => {
  beforeEach(() => {
    (global.fetch as unknown as vi.Mock).mockReset();
  });

  it('renders severity counts from API', async () => {
    (global.fetch as unknown as vi.Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/dashboard/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ cvss_counts: { critical: 5, high: 10, medium: 20, low: 100 } }) });
      }
      if (url.includes('/recent-scans')) {
        return Promise.resolve({ ok: true, json: async () => ({ status: 'success', scans: [] }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({}) });
    });

    render(<ToastProvider><DashboardFull /></ToastProvider>);

    // Wait for numbers to update using labelled counters
    await waitFor(() => expect(screen.getByLabelText('critical-count')).toHaveTextContent('5'));
    expect(screen.getByLabelText('high-count')).toHaveTextContent('10');
    expect(screen.getByLabelText('medium-count')).toHaveTextContent('20');
    expect(screen.getByLabelText('low-count')).toHaveTextContent('100');
  });
});
