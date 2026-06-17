import { test, expect } from '../../../fixtures';

test.describe('ClickFix - Payload Detection and Warnings', () => {
  test('should detect PowerShell payload and show warning', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click the PowerShell copy button
    await page.click('[data-payload="p-powershell"]');
    await page.waitForTimeout(800); // Give extension time to process

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should allow benign text without warning', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click benign copy button
    await page.click('[data-payload="p-benign"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is NOT present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(false);
  });

  test('should detect mshta payload', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click mshta copy button
    await page.click('[data-payload="p-mshta"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should detect rundll32 JavaScript payload', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click rundll32-js copy button
    await page.click('[data-payload="p-rundll-js"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should detect regsvr32 payload', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click regsvr copy button
    await page.click('[data-payload="p-regsvr"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should detect cmd execution payload', async ({ page, extensionId, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click cmd copy button
    await page.click('[data-payload="p-cmd"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should detect macOS pbpaste execution and show warning', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click pbpaste pipe copy button
    await page.click('[data-payload="p-pbpaste-pipe"]');
    await page.waitForTimeout(800); // Give extension time to process and inject

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should detect CMD caret-obfuscated script and show warning', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click cmd-caret copy button
    await page.click('[data-payload="p-cmd-caret"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(true);
  });

  test('should allow whitelisted Homebrew installer command without warning', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click Homebrew copy button
    await page.click('[data-payload="p-whitelisted-brew"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is NOT present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(false);
  });

  test('should allow whitelisted Docker installer command without warning', async ({ page, testPagePath }) => {
    await page.goto(testPagePath);
    await page.waitForLoadState('networkidle');

    // Click Docker copy button
    await page.click('[data-payload="p-whitelisted-docker"]');
    await page.waitForTimeout(800);

    // Verify warning overlay is NOT present
    const warningVisible = await page.locator('#__ss-warning-overlay-host').isVisible();
    expect(warningVisible).toBe(false);
  });
});
