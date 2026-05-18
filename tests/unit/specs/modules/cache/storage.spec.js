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

async function loadStorage() {
  jest.resetModules();
  return import('../../../../../src/background/modules/cache/storage.js');
}

describe('Storage cache wrapper', () => {
  beforeEach(() => {
    backingStore = {};
    global.chrome = { storage: createStorageMock() };
  });

  afterEach(() => {
    delete global.chrome;
    jest.restoreAllMocks();
  });

  test('set/get stores and retrieves namespaced values by module and hostname', async () => {
    const storage = await loadStorage();

    await storage.set('clickfix', 'example.com', { level: 'high' });

    expect(global.chrome.storage.local.set).toHaveBeenCalledWith({
      'threat-sense:clickfix:example.com': expect.objectContaining({ data: { level: 'high' } }),
    });

    const value = await storage.get('clickfix', 'example.com');
    expect(value).toEqual({ level: 'high' });
  });

  test('get returns null and removes key when record is expired by TTL', async () => {
    const storage = await loadStorage();
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(10_000);

    backingStore['threat-sense:clickfix:old.com'] = {
      data: { stale: true },
      ts: 1_000,
    };

    const value = await storage.get('clickfix', 'old.com', 5_000);

    expect(value).toBeNull();
    expect(global.chrome.storage.local.remove).toHaveBeenCalledWith('threat-sense:clickfix:old.com');
    nowSpy.mockRestore();
  });

  test('getAll filters to module namespace and sorts newest-first', async () => {
    const storage = await loadStorage();
    jest.spyOn(Date, 'now').mockReturnValue(50_000);

    backingStore['threat-sense:clickfix:older.com'] = { data: { id: 'older' }, ts: 20_000 };
    backingStore['threat-sense:clickfix:newer.com'] = { data: { id: 'newer' }, ts: 40_000 };
    backingStore['threat-sense:other:ignore.com'] = { data: { id: 'other' }, ts: 45_000 };

    const items = await storage.getAll('clickfix', 40_000);

    expect(items.map((entry) => entry.hostname)).toEqual(['newer.com', 'older.com']);
    expect(items).toEqual([
      { hostname: 'newer.com', data: { id: 'newer' }, ts: 40_000 },
      { hostname: 'older.com', data: { id: 'older' }, ts: 20_000 },
    ]);
  });

  test('clearModule removes only keys in the selected module namespace', async () => {
    const storage = await loadStorage();

    backingStore['threat-sense:clickfix:a.com'] = { data: {}, ts: 1 };
    backingStore['threat-sense:clickfix:b.com'] = { data: {}, ts: 2 };
    backingStore['threat-sense:other:c.com'] = { data: {}, ts: 3 };

    await storage.clearModule('clickfix');

    expect(global.chrome.storage.local.remove).toHaveBeenCalledWith([
      'threat-sense:clickfix:a.com',
      'threat-sense:clickfix:b.com',
    ]);
    expect(backingStore['threat-sense:other:c.com']).toBeDefined();
  });
});