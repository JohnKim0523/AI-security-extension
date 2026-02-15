import { getAIToolName } from '../shared/patterns';
import { DETECTION_PATTERNS } from '../shared/patterns';
import { SEVERITY_ACTIONS, DLPMatch, Action, ExtensionMessage } from '../shared/types';

// =============================================================================
// PROMPT INTERCEPTOR (Content Script)
// Injected into AI tool pages. Hooks into prompt input fields and intercepts
// text BEFORE it gets submitted to the AI model.
//
// KEY DESIGN: All scanning runs SYNCHRONOUSLY in the content script so we can
// call event.preventDefault() before the browser processes the event.
// Results are then sent to the background worker asynchronously for logging.
// =============================================================================

const hostname = window.location.hostname;
const toolName = getAIToolName(hostname);

// Only activate on AI tool pages
if (toolName) {
  console.log(`[DLP] Active on ${toolName} (${hostname})`);
  notifyBackgroundAIDetected();
  initPromptInterception();
}

// ─── NOTIFY BACKGROUND OF AI TOOL ───────────────────────────────
function notifyBackgroundAIDetected() {
  chrome.runtime.sendMessage({
    type: 'AI_TOOL_DETECTED',
    payload: {
      domain: hostname,
      toolName: toolName!,
      url: window.location.href,
    },
  } as ExtensionMessage);
}

// ─── SYNCHRONOUS DLP SCANNER ────────────────────────────────────
// Runs directly in the content script — no async message passing.
// This is what allows us to block events before they go through.
function scanTextSync(text: string): DLPMatch[] {
  if (!text || text.trim().length === 0) return [];

  const matches: DLPMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of DETECTION_PATTERNS) {
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const matchedText = match[0];
      const dedupeKey = `${pattern.name}:${match.index}`;

      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      // Run optional validator (e.g., Luhn check for credit cards)
      if (pattern.validate && !pattern.validate(matchedText)) {
        continue;
      }

      const start = Math.max(0, match.index - 50);
      const end = Math.min(text.length, match.index + matchedText.length + 50);

      matches.push({
        type: pattern.name,
        category: pattern.category,
        severity: pattern.severity,
        action: SEVERITY_ACTIONS[pattern.severity],
        matchedText: maskText(matchedText),
        context: text.substring(start, end),
        timestamp: Date.now(),
      });
    }
  }

  return matches;
}

function maskText(text: string): string {
  if (text.length > 8) {
    return text.substring(0, 3) + '*'.repeat(text.length - 5) + text.substring(text.length - 2);
  }
  return '*'.repeat(text.length);
}

function getHighestAction(matches: DLPMatch[]): Action {
  if (matches.some((m) => m.severity === 'CRITICAL')) return 'BLOCK_ALERT';
  if (matches.some((m) => m.severity === 'HIGH')) return 'BLOCK_LOG';
  if (matches.some((m) => m.severity === 'MEDIUM')) return 'WARN_LOG';
  return 'LOG_ONLY';
}

// ─── MAIN INTERCEPTION LOGIC ────────────────────────────────────
function initPromptInterception() {
  // 1. DOCUMENT-LEVEL paste interceptor — catches ALL pastes on the page
  //    Uses capture phase (3rd arg = true) so it fires BEFORE any other handler
  document.addEventListener('paste', handleDocumentPaste, true);

  // 2. Intercept form submissions
  document.addEventListener('submit', handleFormSubmit, true);

  // 3. Intercept Enter key on textareas and contenteditable divs
  document.addEventListener('keydown', handleKeyDown, true);

  // 4. Intercept send button clicks
  observeSendButtons();

  // 5. Watch for dynamically added input fields
  observeNewInputs();
}

// ─── FORM SUBMIT HANDLER ────────────────────────────────────────
function handleFormSubmit(event: Event) {
  const form = event.target as HTMLFormElement;
  const inputs = form.querySelectorAll('textarea, input[type="text"], [contenteditable="true"]');

  inputs.forEach((input) => {
    const text = getInputText(input as HTMLElement);
    if (text && text.length > 5) {
      scanAndBlock(text, event, 'form_submit');
    }
  });
}

// ─── KEYDOWN HANDLER (Enter to submit) ──────────────────────────
function handleKeyDown(event: KeyboardEvent) {
  if (event.key !== 'Enter' || event.shiftKey) return;

  const target = event.target as HTMLElement;
  if (!isInputElement(target)) return;

  const text = getInputText(target);
  if (text && text.length > 5) {
    scanAndBlock(text, event, 'enter_submit');
  }
}

// ─── SEND BUTTON OBSERVER ───────────────────────────────────────
function observeSendButtons() {
  document.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    const button = target.closest('button[data-testid*="send"], button[aria-label*="Send"], button[aria-label*="submit"]');

    if (!button) return;

    const form = button.closest('form');
    const input = form
      ? form.querySelector('textarea, [contenteditable="true"]')
      : document.querySelector('textarea, [contenteditable="true"]');

    if (input) {
      const text = getInputText(input as HTMLElement);
      if (text && text.length > 5) {
        scanAndBlock(text, event, 'button_click');
      }
    }
  }, true);
}

// ─── DOM MUTATION OBSERVER ──────────────────────────────────────
function observeNewInputs() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (node instanceof HTMLElement) {
          const inputs = node.querySelectorAll?.('textarea, [contenteditable="true"]');
          inputs?.forEach((input) => {
            input.addEventListener('paste', handlePaste, true);
          });
        }
      });
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  document.querySelectorAll('textarea, [contenteditable="true"]').forEach((input) => {
    input.addEventListener('paste', handlePaste, true);
  });
}

// ─── DOCUMENT-LEVEL PASTE HANDLER ───────────────────────────────
// This fires on EVERY paste on the page, regardless of which element.
// Capture phase ensures we run before ChatGPT/Claude's own handlers.
function handleDocumentPaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData('text/plain');
  if (!text || text.length <= 5) return;

  console.log('[DLP] Paste intercepted, scanning...');
  const matches = scanTextSync(text);

  if (matches.length === 0) return;

  const action = getHighestAction(matches);

  if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    console.log('[DLP] BLOCKED paste containing:', matches.map(m => m.type).join(', '));
    showBlockedOverlay(matches);

    // Send to background for logging
    chrome.runtime.sendMessage({
      type: 'SCAN_TEXT',
      payload: { text, source: 'clipboard_paste', url: window.location.href },
    } as ExtensionMessage);
  } else if (action === 'WARN_LOG') {
    showWarningBanner(matches);
    chrome.runtime.sendMessage({
      type: 'SCAN_TEXT',
      payload: { text, source: 'clipboard_paste', url: window.location.href },
    } as ExtensionMessage);
  }
}

// ─── ELEMENT-LEVEL PASTE HANDLER (fallback) ─────────────────────
function handlePaste(event: Event) {
  const clipboardEvent = event as ClipboardEvent;
  const text = clipboardEvent.clipboardData?.getData('text/plain');
  if (text && text.length > 5) {
    scanAndBlock(text, event, 'clipboard_paste');
  }
}

// ─── SCAN AND BLOCK (SYNCHRONOUS) ───────────────────────────────
// This is the critical fix: scan runs synchronously so we can block
// the event BEFORE the browser processes it.
function scanAndBlock(text: string, event: Event, source: string): void {
  const matches = scanTextSync(text);

  if (matches.length === 0) return;

  const action = getHighestAction(matches);

  if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
    // BLOCK IMMEDIATELY — this runs synchronously before the event goes through
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    // For paste events, also clear the clipboard data from reaching the input
    if (event instanceof ClipboardEvent) {
      // The preventDefault above stops the paste
    }

    showBlockedOverlay(matches);
  } else if (action === 'WARN_LOG') {
    showWarningBanner(matches);
  }

  // Send to background for logging (async, fire-and-forget)
  chrome.runtime.sendMessage({
    type: 'SCAN_TEXT',
    payload: { text, source, url: window.location.href },
  } as ExtensionMessage);
}

// ─── UI: BLOCKED OVERLAY ────────────────────────────────────────
function showBlockedOverlay(matches: DLPMatch[]) {
  document.getElementById('dlp-blocked-overlay')?.remove();

  const types = [...new Set(matches.map((m) => m.type))];
  const severity = matches[0]?.severity || 'HIGH';

  const overlay = document.createElement('div');
  overlay.id = 'dlp-blocked-overlay';
  overlay.innerHTML = `
    <div style="
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.5); z-index: 999999;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    ">
      <div style="
        background: white; border-radius: 12px; padding: 32px;
        max-width: 480px; width: 90%; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      ">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
          <div style="
            width: 40px; height: 40px; border-radius: 50%;
            background: #EF4444; display: flex; align-items: center;
            justify-content: center; color: white; font-size: 20px;
          ">!</div>
          <h2 style="margin: 0; font-size: 20px; color: #1F2937;">Sensitive Data Blocked</h2>
        </div>
        <p style="color: #6B7280; margin-bottom: 16px; line-height: 1.5;">
          Your message to <strong>${toolName}</strong> was blocked because it contains
          sensitive data that violates security policy.
        </p>
        <div style="
          background: #FEF2F2; border: 1px solid #FECACA; border-radius: 8px;
          padding: 12px; margin-bottom: 20px;
        ">
          <p style="margin: 0 0 8px; font-weight: 600; color: #991B1B; font-size: 14px;">
            Detected (${severity}):
          </p>
          <ul style="margin: 0; padding-left: 20px; color: #DC2626; font-size: 14px;">
            ${types.map((t) => `<li>${t}</li>`).join('')}
          </ul>
        </div>
        <p style="color: #9CA3AF; font-size: 13px; margin-bottom: 20px;">
          Remove the sensitive data from your message and try again.
          This event has been logged.
        </p>
        <button id="dlp-dismiss-btn" style="
          background: #3B82F6; color: white; border: none; border-radius: 8px;
          padding: 10px 24px; font-size: 14px; cursor: pointer; width: 100%;
          font-weight: 500;
        ">Understood</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  document.getElementById('dlp-dismiss-btn')?.addEventListener('click', () => {
    overlay.remove();
  });
}

// ─── UI: WARNING BANNER ─────────────────────────────────────────
function showWarningBanner(matches: DLPMatch[]) {
  document.getElementById('dlp-warning-banner')?.remove();

  const types = [...new Set(matches.map((m) => m.type))];

  const banner = document.createElement('div');
  banner.id = 'dlp-warning-banner';
  banner.innerHTML = `
    <div style="
      position: fixed; top: 16px; right: 16px; z-index: 999998;
      background: #FFFBEB; border: 1px solid #F59E0B; border-radius: 8px;
      padding: 16px 20px; max-width: 380px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: slideIn 0.3s ease-out;
    ">
      <style>@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }</style>
      <div style="display: flex; justify-content: space-between; align-items: start;">
        <div>
          <p style="margin: 0 0 4px; font-weight: 600; color: #92400E; font-size: 14px;">
            Potential Sensitive Data
          </p>
          <p style="margin: 0; color: #A16207; font-size: 13px;">
            Detected: ${types.join(', ')}
          </p>
        </div>
        <button id="dlp-warning-close" style="
          background: none; border: none; color: #A16207; cursor: pointer;
          font-size: 18px; padding: 0 0 0 12px;
        ">&times;</button>
      </div>
    </div>
  `;

  document.body.appendChild(banner);
  document.getElementById('dlp-warning-close')?.addEventListener('click', () => {
    banner.remove();
  });

  setTimeout(() => banner.remove(), 8000);
}

// ─── HELPERS ────────────────────────────────────────────────────
function getInputText(element: HTMLElement): string {
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    return element.value;
  }
  return element.innerText || element.textContent || '';
}

function isInputElement(element: HTMLElement): boolean {
  return (
    element instanceof HTMLTextAreaElement ||
    element instanceof HTMLInputElement ||
    element.getAttribute('contenteditable') === 'true' ||
    element.getAttribute('role') === 'textbox'
  );
}
