import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { LiveScanPanel } from '../LiveScanPanel';
import { ToastProvider } from '../ui/Toast';

describe('LiveScanPanel', () => {
  test('disables run button when endpoint is empty', async () => {
    render(
      <ToastProvider>
        <LiveScanPanel />
      </ToastProvider>
    );

    const btn = screen.getByRole('button', { name: /run live scan/i });
    expect(btn).toBeDisabled();
  });

  test('runs live scan and shows success toast', async () => {
    // @ts-ignore
    global.fetch = vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ severity: 'low', suggestions: [] }) }));

    render(
      <ToastProvider>
        <LiveScanPanel />
      </ToastProvider>
    );

    const input = screen.getByPlaceholderText(/https:\/\/example.com\/api\/endpoint/i);
    fireEvent.change(input, { target: { value: 'https://example.com/api/endpoint' } });
    const btn = screen.getByRole('button', { name: /run live scan/i });
    fireEvent.click(btn);

    await waitFor(() => expect(screen.getByText(/live scan completed/i)).toBeInTheDocument());

    // @ts-ignore
    global.fetch.mockClear?.();
  });
});
