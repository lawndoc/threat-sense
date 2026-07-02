import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';

async function setupServiceWorker({
  tabs = [{ id: 7, url: 'https://example.com/path' }],
  onClipboardResult = { status: 'not-detected' },
  moduleList = [{ name: 'clickfix', version: '0.1.0' }],
} = {}) {
  jest.resetModules();

  let onMessageListener;

  const registerModule = jest.fn();
  const initializeModules = jest.fn(async () => {});
  const listModules = jest.fn(() => moduleList);

  const clickfixModule = {
    name: 'clickfix',
    version: '0.1.0',
    onClipboardChange: jest.fn(async () => onClipboardResult),
    getStatus: jest.fn(async (hostname) => ({ hostname, status: 'ok' })),
    getHistory: jest.fn(async () => [{ hostname: 'example.com' }]),
  };

  const eventBus = {
    on: jest.fn(),
    emit: jest.fn(),
    once: jest.fn(),
  };

  await jest.unstable_mockModule('../../../../src/background/modules/core/module-registry.js', () => ({
    registerModule,
    initializeModules,
    listModules,
  }));

  await jest.unstable_mockModule('../../../../src/background/modules/core/event-bus.js', () => ({
    default: eventBus,
  }));

  await jest.unstable_mockModule('../../../../src/background/modules/clickfix/index.js', () => ({
    clickfixModule,
  }));

  global.chrome = {
    runtime: {
      onMessage: {
        addListener: jest.fn((listener) => {
          onMessageListener = listener;
        }),
      },
    },
    tabs: {
      query: jest.fn(async () => tabs),
    },
    scripting: {
      executeScript: jest.fn(async () => {}),
    },
  };

  const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

  await import('../../../../src/background/service-worker.js');
  await Promise.resolve();

  return {
    onMessageListener,
    registry: { registerModule, initializeModules, listModules },
    clickfixModule,
    eventBus,
    chrome: global.chrome,
    consoleSpies: { logSpy, errorSpy, warnSpy },
  };
}

async function invokeMessage(onMessageListener, message, sender = {}) {
  const sendResponse = jest.fn();
  const keepAlive = onMessageListener(message, sender, sendResponse);
  expect(keepAlive).toBe(true);
  await new Promise((resolve) => setImmediate(resolve));
  return sendResponse;
}

describe('service-worker message routing', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  afterEach(() => {
    delete global.chrome;
  });

  test('registers module, initializes registry, and installs message listener at startup', async () => {
    const { registry, clickfixModule, eventBus, chrome, onMessageListener } = await setupServiceWorker();

    expect(registry.registerModule).toHaveBeenCalledWith(clickfixModule);
    expect(registry.initializeModules).toHaveBeenCalledWith(eventBus);
    expect(chrome.runtime.onMessage.addListener).toHaveBeenCalledTimes(1);
    expect(typeof onMessageListener).toBe('function');
  });

  test('returns no-active-tab when clipboard message has no sender tab and no active tab found', async () => {
    const { onMessageListener, clickfixModule, chrome } = await setupServiceWorker({ tabs: [] });

    const sendResponse = await invokeMessage(onMessageListener, {
      type: 'CLIPBOARD_CHANGED',
      text: 'payload',
      source: 'offscreen',
    });

    expect(chrome.tabs.query).toHaveBeenCalledWith({ active: true, lastFocusedWindow: true });
    expect(clickfixModule.onClipboardChange).not.toHaveBeenCalled();
    expect(sendResponse).toHaveBeenCalledWith({ ok: false, reason: 'no active tab' });
  });

  test('handles detected clipboard payload by calling module and injecting warning overlay', async () => {
    const { onMessageListener, clickfixModule, chrome } = await setupServiceWorker({
      onClipboardResult: {
        status: 'detected',
        snippet: 'powershell -enc AAAABBBB',
      },
    });

    const sendResponse = await invokeMessage(
      onMessageListener,
      {
        type: 'CLIPBOARD_CHANGED',
        text: 'powershell -enc AAAABBBB',
        source: 'relay',
      },
      {
        tab: { id: 42, url: 'https://attack.example/path' },
      }
    );

    expect(clickfixModule.onClipboardChange).toHaveBeenCalledWith(
      'powershell -enc AAAABBBB',
      42,
      'attack.example'
    );
    expect(chrome.scripting.executeScript).toHaveBeenCalledTimes(2);
    expect(chrome.scripting.executeScript).toHaveBeenNthCalledWith(1, {
      target: { tabId: 42 },
      func: expect.any(Function),
      args: ['powershell -enc AAAABBBB'],
    });
    expect(chrome.scripting.executeScript).toHaveBeenNthCalledWith(2, {
      target: { tabId: 42 },
      files: ['content/warning-overlay.js'],
    });
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, source: 'relay' });
  });

  test('extracts full URL as hostname for file:// protocol links', async () => {
    const { onMessageListener, clickfixModule } = await setupServiceWorker({
      onClipboardResult: {
        status: 'detected',
        snippet: 'powershell -enc AAAABBBB',
      },
    });

    await invokeMessage(
      onMessageListener,
      {
        type: 'CLIPBOARD_CHANGED',
        text: 'powershell -enc AAAABBBB',
        source: 'relay',
      },
      {
        tab: { id: 43, url: 'file:///home/user/document.html' },
      }
    );

    expect(clickfixModule.onClipboardChange).toHaveBeenCalledWith(
      'powershell -enc AAAABBBB',
      43,
      'file:///home/user/document.html'
    );
  });

  test('does not inject warning overlay for non-detected clipboard payloads', async () => {
    const { onMessageListener, chrome } = await setupServiceWorker({
      onClipboardResult: { status: 'not-detected' },
    });

    const sendResponse = await invokeMessage(
      onMessageListener,
      { type: 'CLIPBOARD_CHANGED', text: 'hello world', source: 'relay' },
      { tab: { id: 99, url: 'https://safe.example' } }
    );

    expect(chrome.scripting.executeScript).not.toHaveBeenCalled();
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, source: 'relay' });
  });

  test('routes popup status/history/list messages to module and registry', async () => {
    const { onMessageListener, clickfixModule, registry } = await setupServiceWorker();

    const statusResponse = await invokeMessage(onMessageListener, {
      type: 'GET_CLICKFIX_STATUS',
      payload: { hostname: 'example.com' },
    });
    expect(clickfixModule.getStatus).toHaveBeenCalledWith('example.com');
    expect(statusResponse).toHaveBeenCalledWith({ status: { hostname: 'example.com', status: 'ok' } });

    const historyResponse = await invokeMessage(onMessageListener, { type: 'GET_CLICKFIX_HISTORY' });
    expect(clickfixModule.getHistory).toHaveBeenCalledTimes(1);
    expect(historyResponse).toHaveBeenCalledWith({ history: [{ hostname: 'example.com' }] });

    const listResponse = await invokeMessage(onMessageListener, { type: 'LIST_MODULES' });
    expect(registry.listModules).toHaveBeenCalledTimes(2);
    expect(listResponse).toHaveBeenCalledWith({ modules: [{ name: 'clickfix', version: '0.1.0' }] });
  });

  test('returns structured error response for unknown message types', async () => {
    const { onMessageListener, consoleSpies } = await setupServiceWorker();

    const sendResponse = await invokeMessage(onMessageListener, {
      type: 'NOT_A_REAL_MESSAGE',
    });

    expect(consoleSpies.errorSpy).toHaveBeenCalled();
    expect(sendResponse).toHaveBeenCalledWith({
      error: 'Unknown message type: "NOT_A_REAL_MESSAGE"',
    });
  });
});