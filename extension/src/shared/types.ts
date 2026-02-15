// Severity levels from the DLP target list document
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// Actions per severity
export type Action = 'BLOCK_ALERT' | 'BLOCK_LOG' | 'WARN_LOG' | 'LOG_ONLY';

export const SEVERITY_ACTIONS: Record<Severity, Action> = {
  CRITICAL: 'BLOCK_ALERT',
  HIGH: 'BLOCK_LOG',
  MEDIUM: 'WARN_LOG',
  LOW: 'LOG_ONLY',
};

// A single detection match
export interface DLPMatch {
  type: string;
  category: string;
  severity: Severity;
  action: Action;
  matchedText: string;       // The text that was matched (masked for logging)
  context: string;           // Surrounding text for context
  timestamp: number;
}

// Event sent to the backend for logging
export interface SecurityEvent {
  id: string;
  type: 'DLP_VIOLATION' | 'AI_TOOL_ACCESS' | 'CLIPBOARD_PASTE' | 'FILE_UPLOAD';
  matches: DLPMatch[];
  url: string;
  domain: string;
  action: Action;
  userAgent: string;
  timestamp: number;
}

// Messages between content script and background worker
export type ExtensionMessage =
  | { type: 'SCAN_TEXT'; payload: { text: string; source: string; url: string } }
  | { type: 'SCAN_RESULT'; payload: { matches: DLPMatch[]; action: Action } }
  | { type: 'AI_TOOL_DETECTED'; payload: { domain: string; toolName: string; url: string } }
  | { type: 'GET_STATS'; payload: null }
  | { type: 'STATS_RESPONSE'; payload: DLPStats };

// Stats for the popup UI
export interface DLPStats {
  totalScans: number;
  totalBlocked: number;
  totalWarnings: number;
  recentEvents: SecurityEvent[];
}

// Policy fetched from the backend
export interface DLPPolicy {
  id: string;
  name: string;
  enabled: boolean;
  patterns: PatternRule[];
}

export interface PatternRule {
  type: string;
  category: string;
  severity: Severity;
  regex: string;
  description: string;
  enabled: boolean;
}
