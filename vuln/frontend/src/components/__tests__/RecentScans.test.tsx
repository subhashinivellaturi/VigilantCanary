import React from 'react';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import { RecentScans } from '../RecentScans';
import { ToastProvider } from '../ui/Toast';
import { describe, test, expect, vi } from 'vitest';

describe('RecentScans', () => {
  test('opens scan detail modal and downloads CSV', async () => {
    // @ts-ignore
    global.fetch = vi.fn((url: string) => {
      if (url.includes('/recent-scans')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'success', scans: [{ id: 1, timestamp: '2025-01-01T00:00:00Z', target_url: 'http://example.com/test', scan_types: ['vulnerability'], status: 'completed', total_findings: 1, risk_status: 'High' }] }) });
      }
      if (url.match(/\/scans\/1$/)) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'success', scan: { id: 1, scan_timestamp: '2025-01-01T00:00:00Z', scanned_url: 'http://example.com/test', scan_mode: 'passive_only', findings: [{ finding_id: 'f1', vulnerability_type: 'sql_injection', severity: 'high', cvss_score: 8.5, confidence: 90, description: 'SQLi in param', affected_url: 'http://example.com/test' }], executive_summary: { executive_summary_text: '1 finding', risk_score_0_to_100: 75 } } }) });
      }
      if (url.includes('/export?format=csv')) {
        return Promise.resolve({ ok: true, blob: () => Promise.resolve(new Blob(['f1,sql_injection,high'])) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    render(
      <ToastProvider>
        <RecentScans />
      </ToastProvider>
    );

    // Wait for scan to be listed
    expect(await screen.findByText(/http:\/\/example.com\/test/i)).toBeInTheDocument();

    // Click the View button
    const viewBtn = screen.getByLabelText('View scan details');
    fireEvent.click(viewBtn);

    // Modal should open and display details
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText(/scan details/i)).toBeInTheDocument();
    const withinDialog = within(dialog);
    // The URL may appear in multiple places inside the modal (scanned URL and affected URL), ensure at least one occurrence exists
    expect(withinDialog.getAllByText(/http:\/\/example.com\/test/i).length).toBeGreaterThanOrEqual(1);

    // Click Download CSV inside modal
    const downloadCsvBtn = withinDialog.getByRole('button', { name: /download csv/i });
    fireEvent.click(downloadCsvBtn);

    await waitFor(() => {
      // Ensure export fetch was called
      // @ts-ignore
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/export?format=csv'));
    });

    // Clean up
    // @ts-ignore
    global.fetch.mockClear?.();
  });

  test('shows demo modal when ?demoModal=1 is present in URL', async () => {
    // set url param
    window.history.pushState({}, 'Demo', '/recent-scans?demoModal=1');

    render(
      <ToastProvider>
        <RecentScans />
      </ToastProvider>
    );

    // Modal should be visible with demo data
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText(/demo scan with 2 findings/i)).toBeInTheDocument();
    // risk score should be visible
    expect(screen.getByText(/82/)).toBeInTheDocument();

    // findings should be listed (scope to dialog to avoid other UI text collisions)
    expect(within(dialog).getByText(/sql_injection/i)).toBeInTheDocument();
    // 'xss' may appear in descriptions; ensure at least one matching element is present in dialog
    expect(within(dialog).getAllByText(/xss/i).length).toBeGreaterThanOrEqual(1);

    // Clean up
    // @ts-ignore
    global.fetch.mockClear?.();
  });
});
