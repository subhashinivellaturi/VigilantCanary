/// <reference types="vitest" />
import React from 'react';
import { describe, test, beforeEach, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ToastProvider } from '../ui/Toast';
import { Settings } from '../Settings';

describe('Settings form', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  test('shows validation errors and saves settings to localStorage', async () => {
    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>
    );

    // make a field invalid (rate limit too low)
    const rateInput = screen.getByLabelText(/Rate Limit/i) as HTMLInputElement;
    fireEvent.change(rateInput, { target: { value: '5' } });

    const saveButton = screen.getByRole('button', { name: /Save/i });
    fireEvent.click(saveButton);

    expect(await screen.findByText(/Please fix validation errors/i)).toBeInTheDocument();
    expect(screen.getByText(/Rate limit must be between 10 and 1000/i)).toBeInTheDocument();

    // fix the rate limit
    fireEvent.change(rateInput, { target: { value: '100' } });
    fireEvent.click(saveButton);

    await waitFor(() => expect(screen.getByText(/Settings saved/i)).toBeInTheDocument());

    const stored = JSON.parse(localStorage.getItem('appSettings') || '{}');
    expect(stored.api?.rateLimit).toBe(100);
  });
});
