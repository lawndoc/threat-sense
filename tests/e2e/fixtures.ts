import { test as base, chromium, type BrowserContext } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pathToExtension = path.join(__dirname, '../../src');

const testPagePath = `file://${path.resolve(__dirname, './test-pages/clickfix-test-page.html').replace(/\\/g, '/')}`;

export const test = base.extend<{
  context: BrowserContext;
  extensionId: string;
  testPagePath: string;
}>({
  context: async ({ }, use) => {
    const context = await chromium.launchPersistentContext('', {
      headless: true,
      args: [
        `--disable-extensions-except=${pathToExtension}`,
        `--load-extension=${pathToExtension}`,
      ],
      channel: 'chromium',
    });

    await use(context);
    await context.close();
  },

  extensionId: async ({ context }, use) => {
    // Wait for service worker to load
    let [serviceWorker] = context.serviceWorkers();
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent('serviceworker');
    }

    // Extract extension ID from service worker URL
    // URL format: chrome-extension://<id>/background/service-worker.js
    const extensionId = serviceWorker.url().split('/')[2];

    await use(extensionId);
  },

  testPagePath: async ({ }, use) => {
    await use(testPagePath);
  },
});

export { expect } from '@playwright/test';
