import { describe, test, expect, beforeEach, jest } from '@jest/globals';

async function loadRegistry() {
  jest.resetModules();
  return import('../../../../../src/background/modules/core/module-registry.js');
}

function makeModule(name, overrides = {}) {
  return {
    name,
    version: '1.0.0',
    initialize: jest.fn(async () => {}),
    onRequest: jest.fn(async () => {}),
    getStatus: jest.fn(async () => ({ ok: true })),
    ...overrides,
  };
}

describe('ModuleRegistry', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  test('throws when registering a module missing required fields', async () => {
    const registry = await loadRegistry();

    expect(() => registry.registerModule({ name: 'broken' })).toThrow(
      'Module missing required field: "version"'
    );
  });

  test('skips duplicate module names and keeps first registration', async () => {
    const registry = await loadRegistry();
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const first = makeModule('clickfix', { version: '1.0.0' });
    const duplicate = makeModule('clickfix', { version: '2.0.0' });

    registry.registerModule(first);
    registry.registerModule(duplicate);

    expect(registry.listModules()).toEqual([{ name: 'clickfix', version: '1.0.0' }]);
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  test('initializeModules continues if one module initialization fails', async () => {
    const registry = await loadRegistry();
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const failing = makeModule('failing', {
      initialize: jest.fn(async () => {
        throw new Error('init failed');
      }),
    });
    const healthy = makeModule('healthy');

    registry.registerModule(failing);
    registry.registerModule(healthy);

    await registry.initializeModules({});

    expect(failing.initialize).toHaveBeenCalledTimes(1);
    expect(healthy.initialize).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalled();
  });

  test('dispatchRequest continues even if one module onRequest throws', async () => {
    const registry = await loadRegistry();
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const failing = makeModule('failing', {
      onRequest: jest.fn(async () => {
        throw new Error('request failed');
      }),
    });
    const healthy = makeModule('healthy');

    registry.registerModule(failing);
    registry.registerModule(healthy);

    await registry.dispatchRequest({ url: 'https://example.com' }, { state: 'secure' });

    expect(failing.onRequest).toHaveBeenCalledTimes(1);
    expect(healthy.onRequest).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalled();
  });

  test('getStatusForHost returns per-module error object when module getStatus fails', async () => {
    const registry = await loadRegistry();
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const failing = makeModule('failing', {
      getStatus: jest.fn(async () => {
        throw new Error('status unavailable');
      }),
    });
    const healthy = makeModule('healthy', {
      getStatus: jest.fn(async () => ({ score: 0 })),
    });

    registry.registerModule(failing);
    registry.registerModule(healthy);

    const result = await registry.getStatusForHost('example.com');

    expect(result).toEqual({
      failing: { error: 'status unavailable' },
      healthy: { score: 0 },
    });
    expect(errorSpy).toHaveBeenCalled();
  });
});