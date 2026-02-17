import { getAIToolName, DETECTION_PATTERNS, decodeEvasions, SENSITIVE_FILE_EXTENSIONS, SCANNABLE_FILE_EXTENSIONS } from '../shared/patterns';
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

// ─── SESSION BUFFER (split-message evasion detection) ────────────
let sessionBuffer = '';
let sessionBufferLastUpdate = Date.now();
const SESSION_BUFFER_MAX = 50 * 1024; // 50KB cap
const SESSION_BUFFER_TIMEOUT = 10 * 60 * 1000; // 10 minutes

// ─── TYPING DEBOUNCE STATE ──────────────────────────────────────
const debounceTimers = new WeakMap<HTMLElement, ReturnType<typeof setTimeout>>();

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

  // Scan the original text
  scanWithPatterns(text, matches, seen);

  // Scan decoded versions (base64, URL-encoded, hex, unicode evasion)
  const decodedTexts = decodeEvasions(text);
  for (const decoded of decodedTexts) {
    scanWithPatterns(decoded, matches, seen);
  }

  return matches;
}

function scanWithPatterns(text: string, matches: DLPMatch[], seen: Set<string>): void {
  for (const pattern of DETECTION_PATTERNS) {
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      const matchedText = match[0];
      const dedupeKey = `${pattern.name}:${matchedText}`;

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

  // 5. Watch for dynamically added input fields (+ file inputs)
  observeNewInputs();

  // 6. Drag & Drop blocking
  document.addEventListener('dragover', handleDragOver, true);
  document.addEventListener('drop', handleDrop, true);

  // 7. Typing/input detection (debounced)
  document.addEventListener('input', handleInputEvent, true);

  // 8. Right-click / context menu paste detection
  document.addEventListener('contextmenu', handleContextMenu, true);

  // 9. Print / Print-to-PDF blocking
  window.addEventListener('beforeprint', handleBeforePrint);
  interceptWindowPrint();

  // 10. Autofill detection
  initAutofillBlocking();
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
          // Watch text inputs for paste
          const inputs = node.querySelectorAll?.('textarea, [contenteditable="true"]');
          inputs?.forEach((input) => {
            input.addEventListener('paste', handlePaste, true);
          });
          // Watch file inputs for upload blocking
          const fileInputs = node.querySelectorAll?.('input[type="file"]');
          fileInputs?.forEach((input) => {
            attachFileInputListener(input as HTMLInputElement);
          });
          // If the node itself is a file input
          if (node instanceof HTMLInputElement && node.type === 'file') {
            attachFileInputListener(node);
          }
        }
      });
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  document.querySelectorAll('textarea, [contenteditable="true"]').forEach((input) => {
    input.addEventListener('paste', handlePaste, true);
  });

  // Attach to existing file inputs
  document.querySelectorAll('input[type="file"]').forEach((input) => {
    attachFileInputListener(input as HTMLInputElement);
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
  // Scan the current text
  let matches = scanTextSync(text);

  // Also check session buffer for split-message evasion
  appendToSessionBuffer(text);
  if (sessionBuffer.length > text.length) {
    const bufferMatches = scanTextSync(sessionBuffer);
    // Merge any new matches from the buffer that weren't in the current text
    const currentTypes = new Set(matches.map(m => `${m.type}:${m.matchedText}`));
    for (const bm of bufferMatches) {
      if (!currentTypes.has(`${bm.type}:${bm.matchedText}`)) {
        matches.push(bm);
      }
    }
  }

  if (matches.length === 0) return;

  const action = getHighestAction(matches);

  if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
    // BLOCK IMMEDIATELY — this runs synchronously before the event goes through
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

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

// ─── SESSION BUFFER (split-message evasion) ─────────────────────
function appendToSessionBuffer(text: string): void {
  const now = Date.now();
  // Clear buffer if timed out
  if (now - sessionBufferLastUpdate > SESSION_BUFFER_TIMEOUT) {
    sessionBuffer = '';
  }
  sessionBufferLastUpdate = now;
  sessionBuffer += '\n' + text;
  // Cap buffer size
  if (sessionBuffer.length > SESSION_BUFFER_MAX) {
    sessionBuffer = sessionBuffer.slice(-SESSION_BUFFER_MAX);
  }
}

// Clear session buffer on page navigation
window.addEventListener('beforeunload', () => {
  sessionBuffer = '';
});

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

// ─── DRAG & DROP HANDLERS ───────────────────────────────────────
function handleDragOver(event: DragEvent) {
  // Prevent default to signal we're handling the drop
  event.preventDefault();
}

function handleDrop(event: DragEvent) {
  // Check for dropped files first
  const files = event.dataTransfer?.files;
  if (files && files.length > 0) {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const fileNames = Array.from(files).map(f => f.name);
    console.log('[DLP] BLOCKED file drop:', fileNames);

    showBlockedOverlay([{
      type: 'File Drop',
      category: 'File Upload',
      severity: 'HIGH',
      action: 'BLOCK_LOG',
      matchedText: fileNames.join(', '),
      context: `Dropped ${files.length} file(s): ${fileNames.join(', ')}`,
      timestamp: Date.now(),
    }]);

    chrome.runtime.sendMessage({
      type: 'SCAN_TEXT',
      payload: {
        text: `[FILE DROP] ${fileNames.join(', ')}`,
        source: 'file_drop',
        url: window.location.href,
      },
    } as ExtensionMessage);
    return;
  }

  // Check for dropped text
  const text = event.dataTransfer?.getData('text/plain');
  if (text && text.length > 5) {
    console.log('[DLP] Drop intercepted, scanning...');
    scanAndBlock(text, event, 'drag_drop');
  }
}

// ─── FILE UPLOAD BLOCKING ───────────────────────────────────────
function attachFileInputListener(input: HTMLInputElement) {
  if ((input as any).__dlpFileListenerAttached) return;
  (input as any).__dlpFileListenerAttached = true;

  input.addEventListener('change', handleFileInputChange, true);
}

function handleFileInputChange(event: Event) {
  const input = event.target as HTMLInputElement;
  const files = input.files;
  if (!files || files.length === 0) return;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();

    // Block sensitive file types outright
    if (SENSITIVE_FILE_EXTENSIONS.includes(ext)) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      // Clear the file input
      input.value = '';

      console.log(`[DLP] BLOCKED file upload: ${file.name} (${ext})`);
      showBlockedOverlay([{
        type: 'Sensitive File Upload',
        category: 'File Upload',
        severity: 'CRITICAL',
        action: 'BLOCK_ALERT',
        matchedText: file.name,
        context: `File: ${file.name} (${formatFileSize(file.size)}, type: ${file.type || 'unknown'})`,
        timestamp: Date.now(),
      }]);

      chrome.runtime.sendMessage({
        type: 'SCAN_TEXT',
        payload: {
          text: `[FILE UPLOAD BLOCKED] ${file.name} (${ext}, ${formatFileSize(file.size)})`,
          source: 'file_upload',
          url: window.location.href,
        },
      } as ExtensionMessage);
      return;
    }

    // For scannable text files, read and scan contents
    if (SCANNABLE_FILE_EXTENSIONS.includes(ext) && file.size < 1024 * 1024) {
      const reader = new FileReader();
      reader.onload = () => {
        const content = reader.result as string;
        const matches = scanTextSync(content);
        if (matches.length > 0) {
          const action = getHighestAction(matches);
          if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
            // Can't preventDefault after async read, so clear the input
            input.value = '';
            showBlockedOverlay(matches);

            chrome.runtime.sendMessage({
              type: 'SCAN_TEXT',
              payload: {
                text: content,
                source: 'file_upload_content',
                url: window.location.href,
              },
            } as ExtensionMessage);
          } else if (action === 'WARN_LOG') {
            showWarningBanner(matches);
          }
        }
      };
      reader.readAsText(file);
    }
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ─── TYPING / INPUT DETECTION (DEBOUNCED) ───────────────────────
function handleInputEvent(event: Event) {
  const target = event.target as HTMLElement;
  if (!isInputElement(target)) return;

  // Clear any existing debounce timer for this element
  const existingTimer = debounceTimers.get(target);
  if (existingTimer) clearTimeout(existingTimer);

  // Set a new debounce timer (1500ms)
  const timer = setTimeout(() => {
    const text = getInputText(target);
    if (!text || text.length <= 10) return;

    const matches = scanTextSync(text);
    if (matches.length === 0) return;

    const action = getHighestAction(matches);

    // Show persistent warning bar (not blocking — bad UX to block mid-typing)
    // The existing Enter/button submit handlers will catch and block on submit
    if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
      showPersistentInputWarning(target, matches);
    } else if (action === 'WARN_LOG') {
      showPersistentInputWarning(target, matches);
    }
  }, 1500);

  debounceTimers.set(target, timer);
}

function showPersistentInputWarning(target: HTMLElement, matches: DLPMatch[]) {
  // Remove existing warning for this element
  const existingWarning = target.parentElement?.querySelector('.dlp-input-warning');
  existingWarning?.remove();

  const types = [...new Set(matches.map(m => m.type))];
  const severity = matches[0]?.severity || 'HIGH';

  const warning = document.createElement('div');
  warning.className = 'dlp-input-warning';
  warning.style.cssText = `
    background: ${severity === 'CRITICAL' ? '#FEF2F2' : '#FFFBEB'};
    border: 1px solid ${severity === 'CRITICAL' ? '#FECACA' : '#FDE68A'};
    border-radius: 6px;
    padding: 8px 12px;
    margin-bottom: 4px;
    font-size: 13px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    color: ${severity === 'CRITICAL' ? '#991B1B' : '#92400E'};
    display: flex;
    align-items: center;
    gap: 8px;
    z-index: 999997;
  `;
  warning.innerHTML = `
    <span style="font-weight: 600;">Sensitive data detected:</span>
    <span>${types.join(', ')}</span>
    <span style="margin-left: auto; font-size: 12px; opacity: 0.7;">Submission will be blocked</span>
  `;

  target.parentElement?.insertBefore(warning, target);
}

// ─── CONTEXT MENU (RIGHT-CLICK PASTE) DETECTION ─────────────────
function handleContextMenu(event: Event) {
  const target = event.target as HTMLElement;
  if (!isInputElement(target)) return;

  console.log('[DLP] Context menu opened on input element');

  // After context menu closes, check for content changes via input event
  // Some browsers bypass the paste event for "Paste and Match Style"
  const beforeText = getInputText(target);
  const checkForPaste = () => {
    const afterText = getInputText(target);
    if (afterText !== beforeText && afterText.length > beforeText.length) {
      const newText = afterText;
      if (newText.length > 5) {
        const matches = scanTextSync(newText);
        if (matches.length > 0) {
          const action = getHighestAction(matches);
          if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
            // Revert the input to before the paste
            if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
              target.value = beforeText;
            } else {
              target.textContent = beforeText;
            }
            showBlockedOverlay(matches);

            chrome.runtime.sendMessage({
              type: 'SCAN_TEXT',
              payload: { text: newText, source: 'context_menu_paste', url: window.location.href },
            } as ExtensionMessage);
          } else if (action === 'WARN_LOG') {
            showWarningBanner(matches);
          }
        }
      }
    }
  };

  // Check shortly after context menu action
  setTimeout(checkForPaste, 300);
  setTimeout(checkForPaste, 600);
  setTimeout(checkForPaste, 1000);
}

// ─── PRINT / PRINT-TO-PDF BLOCKING ─────────────────────────────
function handleBeforePrint(event: Event) {
  // Scan visible conversation content on the page
  const conversationText = getVisibleConversationText();
  if (!conversationText || conversationText.length <= 10) return;

  const matches = scanTextSync(conversationText);
  if (matches.length === 0) return;

  const action = getHighestAction(matches);
  if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
    event.preventDefault();
    console.log('[DLP] BLOCKED print — page contains sensitive data');

    showBlockedOverlay([{
      type: 'Print Blocked',
      category: 'Data Exfiltration',
      severity: 'HIGH',
      action: 'BLOCK_LOG',
      matchedText: 'Page contains sensitive data',
      context: `Attempted to print ${toolName} page with ${matches.length} sensitive data match(es)`,
      timestamp: Date.now(),
    }]);

    chrome.runtime.sendMessage({
      type: 'SCAN_TEXT',
      payload: {
        text: `[PRINT BLOCKED] ${matches.map(m => m.type).join(', ')}`,
        source: 'print_blocked',
        url: window.location.href,
      },
    } as ExtensionMessage);
  }
}

function interceptWindowPrint() {
  const originalPrint = window.print.bind(window);
  window.print = () => {
    const conversationText = getVisibleConversationText();
    if (conversationText && conversationText.length > 10) {
      const matches = scanTextSync(conversationText);
      if (matches.length > 0) {
        const action = getHighestAction(matches);
        if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
          console.log('[DLP] BLOCKED window.print() — sensitive data detected');
          showBlockedOverlay([{
            type: 'Print Blocked',
            category: 'Data Exfiltration',
            severity: 'HIGH',
            action: 'BLOCK_LOG',
            matchedText: 'Page contains sensitive data',
            context: `window.print() blocked — ${matches.length} sensitive data match(es)`,
            timestamp: Date.now(),
          }]);
          return;
        }
      }
    }
    originalPrint();
  };
}

function getVisibleConversationText(): string {
  // Common selectors for conversation content across AI tools
  const selectors = [
    '[data-message-author-role]',  // ChatGPT
    '.prose',                       // Claude
    '.message-content',             // Generic
    '.response-content',            // Generic
    'article',                      // Some AI tools
    '[class*="message"]',           // Generic pattern
    '[class*="conversation"]',      // Generic pattern
  ];

  let text = '';
  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach(el => {
      text += ' ' + (el.textContent || '');
    });
    if (text.length > 100) break; // Found content, stop looking
  }

  return text.trim();
}

// ─── AUTOFILL / PASSWORD MANAGER BLOCKING ───────────────────────
function initAutofillBlocking() {
  // Set autocomplete="off" on all input fields within AI tool pages
  disableAutocompleteOnInputs();

  // Detect Chrome autofill animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes dlp-autofill-detect {
      from { opacity: 1; }
      to { opacity: 1; }
    }
    input:-webkit-autofill {
      animation-name: dlp-autofill-detect !important;
    }
  `;
  document.head.appendChild(style);

  document.addEventListener('animationstart', (event) => {
    if (event.animationName === 'dlp-autofill-detect') {
      const target = event.target as HTMLInputElement;
      // Small delay to let autofill complete
      setTimeout(() => {
        const text = target.value;
        if (text && text.length > 5) {
          const matches = scanTextSync(text);
          if (matches.length > 0) {
            const action = getHighestAction(matches);
            if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
              target.value = '';
              showBlockedOverlay(matches);
            } else if (action === 'WARN_LOG') {
              showWarningBanner(matches);
            }
          }
        }
      }, 100);
    }
  });

  // Detect rapid input events (autofill fills multiple fields within 50ms)
  let rapidInputCount = 0;
  let rapidInputTimer: ReturnType<typeof setTimeout> | null = null;

  document.addEventListener('input', (event) => {
    const target = event.target as HTMLElement;
    if (!(target instanceof HTMLInputElement)) return;

    rapidInputCount++;
    if (rapidInputTimer) clearTimeout(rapidInputTimer);

    rapidInputTimer = setTimeout(() => {
      if (rapidInputCount >= 3) {
        // Likely autofill — scan all input values
        console.log('[DLP] Rapid input detected (possible autofill)');
        document.querySelectorAll('input').forEach(input => {
          if (input.value && input.value.length > 5) {
            const matches = scanTextSync(input.value);
            if (matches.length > 0) {
              const action = getHighestAction(matches);
              if (action === 'BLOCK_ALERT' || action === 'BLOCK_LOG') {
                input.value = '';
                showBlockedOverlay(matches);
              }
            }
          }
        });
      }
      rapidInputCount = 0;
    }, 50);
  });
}

function disableAutocompleteOnInputs() {
  document.querySelectorAll('input, textarea').forEach(el => {
    el.setAttribute('autocomplete', 'off');
  });

  // Also observe for new inputs and disable autocomplete on them
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach(node => {
        if (node instanceof HTMLElement) {
          if (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement) {
            node.setAttribute('autocomplete', 'off');
          }
          node.querySelectorAll?.('input, textarea').forEach(el => {
            el.setAttribute('autocomplete', 'off');
          });
        }
      });
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
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
