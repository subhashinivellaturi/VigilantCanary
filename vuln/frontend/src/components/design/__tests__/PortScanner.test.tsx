/// <reference types="vitest" />
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PortScanner } from '../PortScanner';
import { ToastProvider } from '../../ui/Toast';

describe('PortScanner', () => {
  test('validates inputs and shows toast on success', async () => {
    render(
      <ToastProvider>
        <PortScanner />
      </ToastProvider>
    );

    const hostInput = screen.getByPlaceholderText('example.com');
    const portInput = screen.getByPlaceholderText('443');
    const button = screen.getByRole('button', { name: /scan/i });

    // invalid submit
    fireEvent.click(button);
    await waitFor(() => expect(screen.getByText(/host is required/i)).toBeInTheDocument());

    // fill inputs
    fireEvent.change(hostInput, { target: { value: 'localhost' } });
    fireEvent.change(portInput, { target: { value: '8080' } });

    fireEvent.click(button);

    await waitFor(() => expect(screen.getByText(/scan completed for localhost:8080/i)).toBeInTheDocument());
  });
});
