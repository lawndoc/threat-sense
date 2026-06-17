import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';

class FakeButton {
  constructor() {
    this.listeners = new Map();
    this.focus = jest.fn();
  }

  addEventListener(event, handler) {
    this.listeners.set(event, handler);
  }

  click() {
    const handler = this.listeners.get('click');
    if (handler) handler();
  }
}

class FakeShadowRoot {
  constructor() {
    this._innerHTML = '';
    this.dismissButton = new FakeButton();
  }

  set innerHTML(html) {
    this._innerHTML = html;
  }

  get innerHTML() {
    return this._innerHTML;
  }

  querySelector(selector) {
    if (selector === '.overlay__dismiss') {
      return this.dismissButton;
    }
    return null;
  }
}

class FakeElement {
  constructor(tagName, ownerDocument) {
    this.tagName = tagName;
    this.ownerDocument = ownerDocument;
    this.id = '';
    this.parent = null;
    this.attributes = {};
    this.shadowRoot = null;
    this.removed = false;
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
  }

  attachShadow() {
    this.shadowRoot = new FakeShadowRoot();
    return this.shadowRoot;
  }

  remove() {
    this.removed = true;
    if (this.parent) {
      const idx = this.parent.children.indexOf(this);
      if (idx >= 0) {
        this.parent.children.splice(idx, 1);
      }
    }
  }
}

class FakeDocumentRoot {
  constructor() {
    this.children = [];
  }

  appendChild(el) {
    el.parent = this;
    this.children.push(el);
    return el;
  }
}

class FakeDocument {
  constructor() {
    this.documentElement = new FakeDocumentRoot();
  }

  createElement(tagName) {
    return new FakeElement(tagName, this);
  }

  getElementById(id) {
    return this.documentElement.children.find((el) => el.id === id) ?? null;
  }
}

async function runOverlayScript() {
  jest.resetModules();
  await import('../../../../src/content/warning-overlay.js');
}

describe('warning-overlay content script', () => {
  beforeEach(() => {
    global.document = new FakeDocument();
    global.window = {};
  });

  afterEach(() => {
    delete global.document;
    delete global.window;
  });

  test('injects overlay host and focuses dismiss button', async () => {
    window.__ss_overlay_snippet = 'powershell -enc AAAA';

    await runOverlayScript();

    const host = document.getElementById('__ss-warning-overlay-host');
    expect(host).not.toBeNull();
    expect(host.shadowRoot).not.toBeNull();
    expect(host.shadowRoot.querySelector('.overlay__dismiss').focus).toHaveBeenCalledTimes(1);
  });

  test('escapes snippet content before insertion in overlay markup', async () => {
    window.__ss_overlay_snippet = '<script>alert(1)</script> & "quoted"';

    await runOverlayScript();

    const host = document.getElementById('__ss-warning-overlay-host');
    const html = host.shadowRoot.innerHTML;

    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&amp;');
    expect(html).toContain('&quot;quoted&quot;');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  test('is idempotent when script runs more than once', async () => {
    await runOverlayScript();
    const firstHost = document.getElementById('__ss-warning-overlay-host');

    await runOverlayScript();

    const hosts = document.documentElement.children.filter(
      (el) => el.id === '__ss-warning-overlay-host'
    );
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toBe(firstHost);
  });

  test('dismiss button removes overlay host from document', async () => {
    await runOverlayScript();

    const host = document.getElementById('__ss-warning-overlay-host');
    const dismiss = host.shadowRoot.querySelector('.overlay__dismiss');
    dismiss.click();

    expect(document.getElementById('__ss-warning-overlay-host')).toBeNull();
    expect(host.removed).toBe(true);
  });
});