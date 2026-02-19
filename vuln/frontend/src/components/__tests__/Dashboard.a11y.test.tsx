import { render } from '@testing-library/react';
import { describe, test, expect } from 'vitest';
import axe from 'axe-core';
import { Dashboard } from '../Dashboard';

// Run axe on the rendered document
describe('Dashboard accessibility (axe)', () => {
  test('has no detectable accessibility violations', async () => {
    render(<Dashboard />);

    // axe.run expects a node and a callback; use promise-based invocation
    const results = await (axe as any).run(document);

    if (results.violations && results.violations.length > 0) {
      // Format violations for better diagnostics
      const messages = results.violations.map((v: any) => {
        return `${v.id} (${v.impact}):\n  Targets: ${v.nodes.map((n: any) => n.target.join(', ')).join(', ')}\n  HTML: ${v.nodes.map((n: any) => n.html).join('\n---\n')}`;
      }).join('\n\n');
      throw new Error(`Accessibility violations found:\n${messages}`);
    }

    expect(results.violations).toHaveLength(0);
  });
});