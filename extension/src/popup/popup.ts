import { DLPStats, SecurityEvent, ExtensionMessage } from '../shared/types';
import { getAIToolName } from '../shared/patterns';

// =============================================================================
// POPUP UI
// Shows stats and recent events when the user clicks the extension icon.
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  checkCurrentPage();
});

// ─── LOAD STATS FROM BACKGROUND ─────────────────────────────────
function loadStats() {
  chrome.runtime.sendMessage(
    { type: 'GET_STATS', payload: null } as ExtensionMessage,
    (response) => {
      if (!response?.payload) return;
      const stats: DLPStats = response.payload;

      // Update stat numbers
      setText('total-scans', stats.totalScans.toString());
      setText('total-blocked', stats.totalBlocked.toString());
      setText('total-warnings', stats.totalWarnings.toString());

      // Render recent events
      renderEvents(stats.recentEvents);
    },
  );
}

// ─── CHECK CURRENT PAGE ─────────────────────────────────────────
function checkCurrentPage() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url) return;

    try {
      const url = new URL(tab.url);
      const toolName = getAIToolName(url.hostname);
      const statusDot = document.querySelector('#page-status .status-dot') as HTMLElement;
      const statusText = document.getElementById('page-status-text');

      if (toolName) {
        statusDot?.classList.remove('safe');
        statusDot?.classList.add('ai-tool');
        if (statusText) statusText.textContent = `AI Tool Detected: ${toolName} — DLP active`;
      } else {
        if (statusText) statusText.textContent = `${url.hostname} — monitoring clipboard`;
      }
    } catch {
      // chrome:// or other special pages
      const statusText = document.getElementById('page-status-text');
      if (statusText) statusText.textContent = 'System page — no monitoring needed';
    }
  });
}

// ─── RENDER EVENTS LIST ─────────────────────────────────────────
function renderEvents(events: SecurityEvent[]) {
  const list = document.getElementById('events-list');
  if (!list) return;

  if (events.length === 0) return; // Keep the empty state

  list.innerHTML = events
    .slice(0, 10)
    .map((event) => {
      const time = formatTime(event.timestamp);
      const typeClass =
        event.action === 'BLOCK_ALERT' || event.action === 'BLOCK_LOG'
          ? 'blocked'
          : event.action === 'WARN_LOG'
            ? 'warned'
            : 'logged';
      const typeLabel =
        event.action === 'BLOCK_ALERT' || event.action === 'BLOCK_LOG'
          ? 'BLOCKED'
          : event.action === 'WARN_LOG'
            ? 'WARNING'
            : 'LOGGED';
      const detail =
        event.matches.length > 0
          ? event.matches.map((m) => m.type).join(', ')
          : event.type === 'AI_TOOL_ACCESS'
            ? 'AI tool accessed'
            : 'Activity logged';

      return `
        <div class="event-item">
          <div class="event-header">
            <span class="event-type ${typeClass}">${typeLabel}</span>
            <span class="event-time">${time}</span>
          </div>
          <div class="event-domain">${event.domain} — ${detail}</div>
        </div>
      `;
    })
    .join('');
}

// ─── HELPERS ────────────────────────────────────────────────────
function setText(id: string, text: string) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function formatTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return new Date(timestamp).toLocaleDateString();
}
