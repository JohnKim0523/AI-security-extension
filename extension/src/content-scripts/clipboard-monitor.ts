// =============================================================================
// CLIPBOARD MONITOR (Content Script)
// Runs on ALL pages (not just AI tools) to monitor copy events.
// Tracks what sensitive data enters the clipboard so we can warn
// when it's later pasted into an AI tool.
// This is the "clipboard DLP" differentiator from the competitive analysis doc.
// =============================================================================

// Listen for copy events across all pages
document.addEventListener('copy', (event: ClipboardEvent) => {
  // Get the selected/copied text
  const selection = window.getSelection();
  const text = selection?.toString() || '';

  if (!text || text.length < 5) return;

  // Send to background for scanning — we don't block copies,
  // we just flag the clipboard content for later paste-time enforcement
  chrome.runtime.sendMessage({
    type: 'SCAN_TEXT',
    payload: {
      text,
      source: 'clipboard_copy',
      url: window.location.href,
    },
  });
});

// Listen for cut events (same as copy but destructive)
document.addEventListener('cut', (event: ClipboardEvent) => {
  const selection = window.getSelection();
  const text = selection?.toString() || '';

  if (!text || text.length < 5) return;

  chrome.runtime.sendMessage({
    type: 'SCAN_TEXT',
    payload: {
      text,
      source: 'clipboard_cut',
      url: window.location.href,
    },
  });
});
