import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';

let backingStore;

function createStorageMock() {
  return {
    local: {
      set: jest.fn(async (items) => {
        Object.assign(backingStore, items);
      }),
      get: jest.fn(async (key) => {
        if (key === null) {
          return { ...backingStore };
        }
        if (typeof key === 'string') {
          return Object.prototype.hasOwnProperty.call(backingStore, key)
            ? { [key]: backingStore[key] }
            : {};
        }
        return {};
      }),
      remove: jest.fn(async (keyOrKeys) => {
        const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys];
        for (const key of keys) {
          delete backingStore[key];
        }
      }),
    },
  };
}

async function loadClickfixModule() {
  jest.resetModules();
  const { clickfixModule } = await import('../../../../../src/background/modules/clickfix/index.js');
  return clickfixModule;
}

describe('ClickFix Module Index', () => {
  beforeEach(() => {
    backingStore = {};
    global.chrome = {
      storage: createStorageMock(),
      offscreen: {
        hasDocument: jest.fn(async () => false),
        createDocument: jest.fn(async () => {}),
      },
      runtime: {
        getURL: jest.fn((path) => `chrome-extension://id/${path}`),
      },
    };
  });

  afterEach(() => {
    delete global.chrome;
    jest.restoreAllMocks();
  });

  test('onClipboardChange appends detections to array and getStatus returns latest', async () => {
    const clickfixModule = await loadClickfixModule();

    // 1. First threat detection
    const payload1 = 's^t^a^r^t cmd';
    const res1 = await clickfixModule.onClipboardChange(payload1, 1, 'example.com');
    expect(res1.status).toBe('detected');

    // Verify it is stored as an array
    const stored = backingStore['threat-sense:clickfix:example.com'];
    expect(stored).toBeDefined();
    expect(Array.isArray(stored.data)).toBe(true);
    expect(stored.data.length).toBe(1);
    expect(stored.data[0].indicator.label).toBe('CMD caret obfuscation');

    // getStatus should return the single item
    const status1 = await clickfixModule.getStatus('example.com');
    expect(status1).not.toBeNull();
    expect(status1.indicator.label).toBe('CMD caret obfuscation');

    // 2. Second threat detection on same hostname
    const payload2 = 'powershell.exe IEX downloadstring';
    const res2 = await clickfixModule.onClipboardChange(payload2, 1, 'example.com');
    expect(res2.status).toBe('detected');

    // Verify both are stored
    const stored2 = backingStore['threat-sense:clickfix:example.com'];
    expect(stored2.data.length).toBe(2);
    expect(stored2.data[0].indicator.label).toBe('CMD caret obfuscation');
    expect(stored2.data[1].indicator.label).toBe('PowerShell download-execute');

    // getStatus should return the latest detection
    const status2 = await clickfixModule.getStatus('example.com');
    expect(status2.indicator.label).toBe('PowerShell download-execute');
  });

  test('getHistory flattens and sorts history items newest-first', async () => {
    const clickfixModule = await loadClickfixModule();
    const now = Date.now();

    const t1 = now - 3000;
    const t2 = now - 2000;
    const t3 = now - 1000;

    // Setup history with different hostnames and timestamps
    backingStore['threat-sense:clickfix:host-a.com'] = {
      data: [
        { status: 'detected', indicator: { label: 'Threat A1' }, detectedAt: t1, hostname: 'host-a.com' },
        { status: 'detected', indicator: { label: 'Threat A2' }, detectedAt: t3, hostname: 'host-a.com' },
      ],
      ts: t3,
    };
    backingStore['threat-sense:clickfix:host-b.com'] = {
      data: [
        { status: 'detected', indicator: { label: 'Threat B1' }, detectedAt: t2, hostname: 'host-b.com' },
      ],
      ts: t2,
    };

    const history = await clickfixModule.getHistory();
    // Should have 3 items total, flattened
    expect(history.length).toBe(3);

    // Sorted newest first: A2 (t3) -> B1 (t2) -> A1 (t1)
    expect(history[0].data.indicator.label).toBe('Threat A2');
    expect(history[0].hostname).toBe('host-a.com');
    expect(history[0].ts).toBe(t3);

    expect(history[1].data.indicator.label).toBe('Threat B1');
    expect(history[1].hostname).toBe('host-b.com');
    expect(history[1].ts).toBe(t2);

    expect(history[2].data.indicator.label).toBe('Threat A1');
    expect(history[2].hostname).toBe('host-a.com');
    expect(history[2].ts).toBe(t1);
  });
});
