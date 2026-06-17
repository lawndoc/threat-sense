/**
 * EventBus — lightweight pub/sub for internal module communication.
 *
 * Events flow within the service worker. For popup/content-script
 * communication, use chrome.runtime.sendMessage instead.
 */

const listeners = new Map();

/**
 * Subscribe to an event.
 * @param {string} event
 * @param {Function} handler
 * @returns {Function} unsubscribe function
 */
export function on(event, handler) {
  if (!listeners.has(event)) {
    listeners.set(event, new Set());
  }
  listeners.get(event).add(handler);
  return () => listeners.get(event)?.delete(handler);
}

/**
 * Publish an event to all subscribers.
 * @param {string} event
 * @param {*} payload
 */
export function emit(event, payload) {
  const handlers = listeners.get(event);
  if (!handlers) return;
  for (const handler of handlers) {
    try {
      handler(payload);
    } catch (err) {
      console.error(`[EventBus] Handler error for "${event}":`, err);
    }
  }
}

/**
 * Subscribe to an event exactly once.
 * @param {string} event
 * @param {Function} handler
 */
export function once(event, handler) {
  const unsub = on(event, (payload) => {
    handler(payload);
    unsub();
  });
}

export default { on, emit, once };
