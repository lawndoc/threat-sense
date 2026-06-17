import { test, expect } from '../../../fixtures';

test.describe('ClickFix - Test Page Functionality', () => {
  test('should load test page successfully', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);

    const title = await page.title();
    expect(title).toContain('Threat Sense');
    expect(title).toContain('ClickFix');
  });

  test('should display all test scenarios', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Verify benign control section
    await expect(page.locator('[data-payload="p-benign"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-whitelisted-brew"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-whitelisted-docker"]')).toBeVisible();

    // Verify high confidence detections
    await expect(page.locator('[data-payload="p-powershell"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-mshta"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-rundll-js"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-regsvr"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-cmd"]')).toBeVisible();

    // Verify new heuristics
    await expect(page.locator('[data-payload="p-pbpaste-pipe"]')).toBeVisible();
    await expect(page.locator('[data-payload="p-cmd-caret"]')).toBeVisible();
  });

  test('should display badges correctly', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Verify benign badge
    await expect(page.locator('.badge-none').first()).toBeVisible();

    // Verify high-confidence badge
    const highBadges = await page.locator('.badge-high').all();
    expect(highBadges.length).toBeGreaterThan(0);
  });

  test('should display payload code blocks', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    const codeBlocks = await page.locator('code').all();
    expect(codeBlocks.length).toBeGreaterThan(0);

    // Verify specific payloads are present
    const pageContent = await page.content();
    expect(pageContent).toContain('powershell');
    expect(pageContent).toContain('mshta');
    expect(pageContent).toContain('rundll32');
  });
});

test.describe('ClickFix - Copy Button Interactions', () => {
  test('should handle copy button clicks', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Get initial button count
    const buttons = await page.locator('button.copy-btn').all();
    expect(buttons.length).toBeGreaterThan(0);

    // Click the first copy button (benign text) and verify the click actually executed
    await page.click('button.copy-btn:first-of-type');
    await page.waitForTimeout(800);

    // Verify the toast appeared, proving the clipboard write handler ran
    await expect(page.locator('#toast')).toBeVisible();

    // Verify the warning overlay did NOT appear for benign content
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(false);
  });

  test('should display toast notification on copy', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click copy button
    await page.click('button.copy-btn:first-of-type');

    // Check for toast element
    await expect(page.locator('#toast')).toBeVisible();
  });
});
