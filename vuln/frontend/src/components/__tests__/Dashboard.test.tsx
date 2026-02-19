import React from 'react';
import { render, screen } from '@testing-library/react';
import { Dashboard } from '../Dashboard';
import { describe, test, expect } from 'vitest';

describe('Dashboard accessibility and render', () => {
  test('renders executive summary and recent activity regions', () => {
    render(<Dashboard />);

    expect(screen.getByRole('region', { name: /executive summary/i })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: /recent activity/i })).toBeInTheDocument();
  });

  test('Quick Actions links exist and are accessible', () => {
    render(<Dashboard />);

    const runLink = screen.getByRole('link', { name: /run quick vulnerability scan/i });
    const viewLink = screen.getByRole('link', { name: /view recent scans/i });

    expect(runLink).toBeInTheDocument();
    expect(runLink).toHaveAttribute('href', '/scanner');
    expect(viewLink).toBeInTheDocument();
    expect(viewLink).toHaveAttribute('href', '/recent-scans');
  });

  test('Severity cards are present and have correct labels', () => {
    render(<Dashboard />);

    expect(screen.getByRole('heading', { name: /critical/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /high/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /medium/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /low/i })).toBeInTheDocument();
  });
});