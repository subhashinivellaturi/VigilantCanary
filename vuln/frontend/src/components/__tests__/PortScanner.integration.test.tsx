import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PortScanner } from '../PortScanner';
import { ToastProvider } from '../ui/Toast';

describe('PortScanner (integration)', () => {
  test('performs a port scan and shows success toast', async () => {
    // @ts-ignore
    global.fetch = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({ open_count: 2, total_scanned: 100, open_ports: [{ port: 22, service: 'ssh' }] }) })
    );

    render(
      <ToastProvider>
        <PortScanner />
      </ToastProvider>
    );

    const input = screen.getByPlaceholderText(/192.168.1.1 or example.com/i);
    const btn = screen.getByRole('button', { name: /start port scan/i });

    fireEvent.change(input, { target: { value: '192.168.1.1' } });
    fireEvent.click(btn);

    await waitFor(() => expect(screen.getByText(/port scan completed/i)).toBeInTheDocument());
    const matches = await screen.findAllByText(/open ports/i);
    expect(matches.find((el) => el.tagName.toLowerCase() === 'h4')).toBeTruthy();

    // @ts-ignore
    global.fetch.mockClear?.();
  });
});
