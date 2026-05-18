# Threat Sense Testing Guide

This document explains how to run and extend automated tests for Threat Sense.

## Setup

Install dependencies before running tests:

```bash
npm install
```

## Test Types

### Unit Tests (Jest)

Location: `tests/unit/specs/`

Unit tests validate module behavior and contracts without a real browser.

### E2E Tests (Playwright)

Location: `tests/e2e/`

E2E tests validate extension behavior in Chromium with the extension loaded.

## Unit Test Structure Conventions

Unit tests use a `specs` folder intentionally (not Playwright-specific).

- `specs` means test specifications; it is framework-neutral.
- Mirror `src` domains where practical so contributors can find tests quickly.
- Keep test filenames as `*.spec.js`.
- Prefer one file per unit boundary (module, orchestrator, content script).

Current layout:

```text
tests/unit/specs/
  background/
    service-worker.spec.js
  content/
    warning-overlay.spec.js
  modules/
    cache/
      storage.spec.js
    clickfix/
      detector.spec.js
    core/
      module-registry.spec.js
```

## Running Tests

Run unit tests:

```bash
npm test
```

Run unit tests in watch mode:

```bash
npm run test:watch
```

Run unit tests with coverage:

```bash
npm run test:coverage
```

Run all e2e tests:

```bash
npm run test:e2e
```

Run e2e tests in headed mode:

```bash
npm run test:e2e:headed
```

Run e2e tests in debug mode:

```bash
npm run test:e2e:debug
```

Run one e2e spec file:

```bash
npx playwright test --config tests/playwright.config.ts tests/e2e/specs/extension-loading.spec.ts
```

Run e2e tests by name pattern:

```bash
npx playwright test --config tests/playwright.config.ts -g "should detect PowerShell"
```

Run all tests:

```bash
npm run test:all
```

## Test Artifacts

- Unit test output goes to terminal.
- E2E HTML report is generated at `playwright-report/index.html`.
- Open e2e report with:

```bash
npx playwright show-report
```

## Manual Test Page

Manual scenarios live at `tests/e2e/test-pages/clickfix-test-page.html`.

To test manually:

1. Load extension from `src/` in `chrome://extensions`.
2. Open `tests/e2e/test-pages/clickfix-test-page.html` in a tab.
3. Click payload copy buttons.
4. Confirm warning overlay appears for malicious payloads.

## Troubleshooting

### Unit Tests and ES Modules

- Ensure `package.json` contains `"type": "module"`.
- Use `.js` extensions in imports.

### Playwright Cannot Load Extension

- Verify `src/manifest.json` exists.
- Verify extension path setup in `tests/e2e/fixtures.ts`.
- Install Chromium if needed:

```bash
npx playwright install chromium
```

### Service Worker Not Found

- Extension startup can be delayed; fixtures already wait for `serviceworker`.
- Confirm `src/manifest.json` defines a background service worker.

### Timeout Errors

- Increase timeout in `tests/playwright.config.ts` if needed.
- Use `npm run test:e2e:debug` for investigation.

## Adding New Tests

### New Unit Test

Add under the matching domain in `tests/unit/specs/`.

Example:

```javascript
test('detects new payload pattern', () => {
  const result = analyzeClipboard('new malicious pattern');
  expect(result.status).toBe('detected');
});
```

### New E2E Test

Add to `tests/e2e/specs/`.

Example:

```typescript
test('does something', async ({ page }) => {
  await page.goto('file:///.../tests/e2e/test-pages/clickfix-test-page.html');
});
```

## Best Practices

1. Keep tests focused on behavior contracts.
2. Prefer stable assertions over implementation details.
3. Mock external APIs in unit tests.
4. Run `npm run test:all` before opening a PR.
5. Add tests when adding or changing security behavior.

## Further Reading

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Playwright Documentation](https://playwright.dev/docs/intro)
- [Playwright Chrome Extension Testing](https://playwright.dev/docs/chrome-extensions)
