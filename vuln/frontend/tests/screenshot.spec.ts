import { test, expect } from '@playwright/test';
import fs from 'fs';

test('capture scan detail and dashboard screenshots', async ({ page }) => {
  // Ensure artifacts dir exists
  fs.mkdirSync('artifacts/screenshots', { recursive: true });

  // Scan detail (demo modal)
  await page.goto('http://localhost:5174/recent-scans?demoModal=1');
  await page.waitForSelector('[role="dialog"]');
  const dialog = page.locator('[role="dialog"]');
  await dialog.screenshot({ path: 'artifacts/screenshots/scan-detail.png', fullPage: true });

  // Dashboard-full
  await page.goto('http://localhost:5174/dashboard-full');
  await page.waitForSelector('text=Vulnerability Severity Breakdown');
  await page.screenshot({ path: 'artifacts/screenshots/dashboard-full.png', fullPage: true });
});
