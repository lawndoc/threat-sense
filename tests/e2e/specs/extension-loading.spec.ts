import { test, expect } from '../fixtures';

test.describe('Extension Loading and Initialization', () => {
  test('should load extension with valid ID', async ({ page, extensionId, context }) => {
    expect(extensionId).toBeTruthy();
    expect(extensionId.length).toBeGreaterThan(0);

    // Extension ID should be a valid Chrome extension ID format
    expect(/^[a-z]{32}$/.test(extensionId)).toBe(true);
  });

  test('should have service worker running', async ({ context }) => {
    let [serviceWorker] = context.serviceWorkers();
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent('serviceworker', { timeout: 5000 });
    }
    expect(serviceWorker).toBeTruthy();

    const url = serviceWorker.url();
    expect(url).toContain('chrome-extension://');
    expect(url).toContain('service-worker.js');
  });

  test('should have content scripts injected', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);

    // Check if the clipboard interceptor has wrapped writeText
    const isWrapped = await page.evaluate(() => {
      return !navigator.clipboard.writeText.toString().includes('[native code]');
    });

    expect(isWrapped).toBe(true);
  });
});
