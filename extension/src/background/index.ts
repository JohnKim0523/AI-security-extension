import { DLPEngine } from './dlp-engine';
import { getAIToolName, SENSITIVE_DOWNLOAD_EXTENSIONS } from '../shared/patterns';
import { SecurityEvent, DLPStats, ExtensionMessage, DLPMatch, Action } from '../shared/types';

// =============================================================================
// BACKGROUND SERVICE WORKER
// This is the "brain" of the extension — runs persistently, handles all logic.
// Think of it like your NestJS main.ts + app.service.ts combined.
// =============================================================================

const dlpEngine = new DLPEngine();

// In-memory stats (persisted to chrome.storage periodically)
let stats: DLPStats = {
  totalScans: 0,
  totalBlocked: 0,
  totalWarnings: 0,
  recentEvents: [],
};

// Backend API URL
const API_BASE_URL = 'https://ai-security-extension-production.up.railway.app';

// ─── MESSAGE HANDLER ─────────────────────────────────────────────
// Listens for messages from content scripts (like a NestJS controller)
chrome.runtime.onMessage.addListener(
  (message: ExtensionMessage, _sender, sendResponse) => {
    switch (message.type) {
      case 'SCAN_TEXT':
        handleScanRequest(message.payload, sendResponse);
        return true; // Keep channel open for async response

      case 'GET_STATS':
        sendResponse({ type: 'STATS_RESPONSE', payload: stats });
        return false;

      case 'AI_TOOL_DETECTED':
        handleAIToolDetected(message.payload);
        return false;

      default:
        return false;
    }
  },
);

// ─── SCAN REQUEST HANDLER ────────────────────────────────────────
function handleScanRequest(
  payload: { text: string; source: string; url: string },
  sendResponse: (response: any) => void,
) {
  const { text, source, url } = payload;
  stats.totalScans++;

  const matches = dlpEngine.scan(text);

  if (matches.length === 0) {
    sendResponse({ type: 'SCAN_RESULT', payload: { matches: [], action: 'LOG_ONLY' as Action } });
    return;
  }

  const action = dlpEngine.getHighestAction(matches);

  // Track stats
  if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
    stats.totalBlocked++;
  } else if (action === 'WARN_LOG') {
    stats.totalWarnings++;
  }

  // Create security event
  const event: SecurityEvent = {
    id: crypto.randomUUID(),
    type: 'DLP_VIOLATION',
    matches,
    url,
    domain: new URL(url).hostname,
    action,
    userAgent: navigator.userAgent,
    timestamp: Date.now(),
  };

  // Store in recent events (keep last 50)
  stats.recentEvents.unshift(event);
  if (stats.recentEvents.length > 50) {
    stats.recentEvents = stats.recentEvents.slice(0, 50);
  }

  // Persist stats
  chrome.storage.local.set({ dlpStats: stats });

  // Send event to backend (fire and forget)
  sendEventToBackend(event);

  // Show notification for critical/high severity
  if (action === 'BLOCK_ALERT') {
    showNotification(matches);
  }

  sendResponse({ type: 'SCAN_RESULT', payload: { matches, action } });
}

// ─── AI TOOL DETECTION ───────────────────────────────────────────
function handleAIToolDetected(payload: { domain: string; toolName: string; url: string }) {
  const event: SecurityEvent = {
    id: crypto.randomUUID(),
    type: 'AI_TOOL_ACCESS',
    matches: [],
    url: payload.url,
    domain: payload.domain,
    action: 'LOG_ONLY',
    userAgent: navigator.userAgent,
    timestamp: Date.now(),
  };

  stats.recentEvents.unshift(event);
  sendEventToBackend(event);
}

// ─── TAB MONITORING ──────────────────────────────────────────────
// Watch for navigation to AI tool domains
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;

  try {
    const url = new URL(tab.url);
    const toolName = getAIToolName(url.hostname);

    if (toolName) {
      // Set badge to indicate AI tool detected
      chrome.action.setBadgeText({ text: 'AI', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#F59E0B', tabId });
    }
  } catch {
    // Invalid URL, ignore
  }
});

// ─── BACKEND COMMUNICATION ──────────────────────────────────────
async function sendEventToBackend(event: SecurityEvent): Promise<void> {
  try {
    await fetch(`${API_BASE_URL}/api/logging/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    });
  } catch {
    // Backend unavailable — events are still stored locally
    console.warn('[DLP] Backend unavailable, event stored locally');
  }
}

// ─── NOTIFICATIONS ──────────────────────────────────────────────
function showNotification(matches: DLPMatch[]) {
  const types = [...new Set(matches.map((m) => m.type))];
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-48.png',
    title: 'Sensitive Data Blocked',
    message: `Detected: ${types.join(', ')}. This data was prevented from being sent to an AI tool.`,
    priority: 2,
  });
}

// ─── DOWNLOAD MONITORING ────────────────────────────────────────
// Monitor downloads originating from AI tool domains
chrome.downloads.onCreated.addListener((downloadItem) => {
  const referrer = downloadItem.referrer || '';
  const url = downloadItem.url || '';
  const filename = downloadItem.filename || '';

  // Check if download originated from an AI tool domain
  let aiToolName: string | null = null;
  try {
    if (referrer) {
      const refUrl = new URL(referrer);
      aiToolName = getAIToolName(refUrl.hostname);
    }
    if (!aiToolName && url) {
      const dlUrl = new URL(url);
      aiToolName = getAIToolName(dlUrl.hostname);
    }
  } catch {
    // Invalid URL, skip
  }

  if (!aiToolName) return;

  // Determine severity based on file extension
  const ext = '.' + filename.split('.').pop()?.toLowerCase();
  const isSensitive = SENSITIVE_DOWNLOAD_EXTENSIONS.includes(ext);

  const severity: 'HIGH' | 'MEDIUM' = isSensitive ? 'HIGH' : 'MEDIUM';

  console.log(`[DLP] Download from ${aiToolName}: ${filename} (${severity})`);

  const event: SecurityEvent = {
    id: crypto.randomUUID(),
    type: 'DOWNLOAD_FROM_AI',
    matches: [{
      type: `Download from ${aiToolName}`,
      category: 'Data Exfiltration',
      severity,
      action: isSensitive ? 'BLOCK_LOG' : 'WARN_LOG',
      matchedText: filename,
      context: `File: ${filename}, Source: ${aiToolName}, URL: ${url.substring(0, 200)}`,
      timestamp: Date.now(),
    }],
    url: referrer || url,
    domain: aiToolName,
    action: isSensitive ? 'BLOCK_LOG' : 'WARN_LOG',
    userAgent: navigator.userAgent,
    timestamp: Date.now(),
  };

  // Track stats
  if (isSensitive) {
    stats.totalWarnings++;
  }

  stats.recentEvents.unshift(event);
  if (stats.recentEvents.length > 50) {
    stats.recentEvents = stats.recentEvents.slice(0, 50);
  }

  chrome.storage.local.set({ dlpStats: stats });
  sendEventToBackend(event);

  // Show notification for sensitive file downloads
  if (isSensitive) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon-48.png',
      title: 'AI Tool Download Detected',
      message: `Sensitive file downloaded from ${aiToolName}: ${filename}`,
      priority: 2,
    });
  }
});

// ─── STARTUP ────────────────────────────────────────────────────
// Load persisted stats on startup
chrome.storage.local.get('dlpStats', (result) => {
  if (result.dlpStats) {
    stats = result.dlpStats;
  }
});

console.log('[DLP] Background service worker initialized');
