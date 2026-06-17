/**
 * Popup script — queries the service worker for ClickFix data and renders the UI.
 */

// ── DOM refs ──────────────────────────────────────────────────────────────────

const $hostname      = document.getElementById('current-hostname');
const $badge         = document.getElementById('status-badge');
const $badgeIcon     = document.getElementById('status-icon');
const $badgeLabel    = document.getElementById('status-label');
const $clickfixList  = document.getElementById('clickfix-history-list');

// ── Helpers ───────────────────────────────────────────────────────────────────

function send(type, payload = {}) {
  return new Promise((resolve) => chrome.runtime.sendMessage({ type, payload }, resolve));
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Render helpers ────────────────────────────────────────────────────────────

function renderBadge(status) {
  if (status) {
    $badge.dataset.status = 'error';
    $badgeIcon.textContent  = '⚠️';
    $badgeLabel.textContent = `Threat detected on this site`;
  } else {
    $badge.dataset.status = 'unknown';
    $badgeIcon.textContent  = '✅';
    $badgeLabel.textContent = 'No threats on this site';
  }
}

function renderClickfixHistory(entries) {
  if (!entries || entries.length === 0) return;

  $clickfixList.innerHTML = '';
  for (const entry of entries.slice(0, 20)) {
    const li = document.createElement('li');
    li.className = 'history__item';

    const dot = document.createElement('span');
    dot.className = 'history__dot history__dot--error';

    const name = document.createElement('span');
    name.className = 'history__hostname';
    name.textContent = entry.hostname;
    name.title = entry.hostname;

    const label = document.createElement('span');
    label.className = 'history__algo';
    label.textContent = entry.data.indicator?.label ?? '';

    const time = document.createElement('span');
    time.className = 'history__time';
    time.textContent = timeAgo(entry.ts);

    li.append(dot, name, label, time);
    $clickfixList.appendChild(li);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function init() {
  // Get current tab hostname
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  let hostname = null;
  try {
    hostname = tab?.url ? new URL(tab.url).hostname : null;
  } catch {
    /* non-url tab (e.g. chrome://) */
  }

  $hostname.textContent = hostname ?? 'N/A';

  // Check if this site has a ClickFix detection
  if (hostname) {
    const { status } = await send('GET_CLICKFIX_STATUS', { hostname });
    renderBadge(status);
  } else {
    renderBadge(null);
  }

  // ClickFix threat history
  const { history: clickfixHistory } = await send('GET_CLICKFIX_HISTORY');
  renderClickfixHistory(clickfixHistory);
}

init().catch(console.error);
