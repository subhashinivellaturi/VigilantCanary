import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'vuln/frontend/tests',
  timeout: 60_000,
  expect: { timeout: 5000 },
  fullyParallel: true,
  reporter: [['list'], ['html', { outputFolder: 'artifacts/playwright-report' }]],
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } }
  ],
  webServer: {
    command: 'npm run dev --prefix vuln/frontend',
    url: 'http://localhost:5174',
    reuseExistingServer: true,
    timeout: 120_000,
  },
  outputDir: 'artifacts/playwright'
});
