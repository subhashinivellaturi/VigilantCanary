/// <reference types="vitest" />
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SecurityAssistant } from '../SecurityAssistant';
import { ToastProvider } from '../../ui/Toast';

describe('SecurityAssistant', () => {
  test('sends and receives messages', async () => {
    render(
      <ToastProvider>
        <SecurityAssistant />
      </ToastProvider>
    );

    const input = screen.getByPlaceholderText(/ask the assistant/i);
    const send = screen.getByRole('button', { name: /send/i });

    fireEvent.click(send);
    await waitFor(() => expect(screen.getByText(/please enter a message/i)).toBeInTheDocument());

    fireEvent.change(input, { target: { value: 'What did the last scan find?' } });
    fireEvent.click(send);

    await waitFor(() => expect(screen.getByText(/what did the last scan find\?/i)).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/simulated response to/i)).toBeInTheDocument());
  });
});
