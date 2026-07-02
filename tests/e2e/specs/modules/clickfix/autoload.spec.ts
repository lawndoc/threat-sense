import { test, expect } from '../../../fixtures';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const autoloadPagePath = `file://${path.resolve(__dirname, '../../../test-pages/autoload-clickfix.html').replace(/\\/g, '/')}`;

test.describe('ClickFix - Autoload Payload Detection', () => {
  test('should automatically detect PowerShell payload on page load', async ({ page }) => {
    // Navigate to the realistic autoload clickfix page
    await page.goto(autoloadPagePath);
    await page.waitForLoadState('networkidle');

    // Wait a brief moment for the extension's interceptor and service worker to process
    await page.waitForTimeout(1000);

    // Verify warning overlay is present automatically without user click interaction
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });
});
