import { DETECTION_PATTERNS, DetectionPattern } from '../shared/patterns';
import { DLPMatch, Severity, SEVERITY_ACTIONS, Action } from '../shared/types';

// =============================================================================
// DLP DETECTION ENGINE
// Layer 1: Fast regex pre-filter (from the architecture in the target list doc)
// This is the Tier 1 + Tier 2 detection — runs on every prompt in <20ms
// =============================================================================

export class DLPEngine {
  private patterns: DetectionPattern[];

  constructor() {
    this.patterns = DETECTION_PATTERNS;
  }

  /**
   * Scan text for sensitive data patterns.
   * Returns all matches with severity and recommended action.
   */
  scan(text: string): DLPMatch[] {
    if (!text || text.trim().length === 0) return [];

    const matches: DLPMatch[] = [];
    const seen = new Set<string>(); // Deduplicate overlapping matches

    for (const pattern of this.patterns) {
      // Reset regex state (important for /g flag)
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

        // Extract surrounding context (50 chars each side)
        const start = Math.max(0, match.index - 50);
        const end = Math.min(text.length, match.index + matchedText.length + 50);
        const context = text.substring(start, end);

        matches.push({
          type: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          action: SEVERITY_ACTIONS[pattern.severity],
          matchedText: this.maskSensitive(matchedText, pattern.severity),
          context: this.maskSensitive(context, pattern.severity),
          timestamp: Date.now(),
        });
      }
    }

    return matches;
  }

  /**
   * Determine the highest-severity action from a set of matches.
   * CRITICAL > HIGH > MEDIUM > LOW
   */
  getHighestAction(matches: DLPMatch[]): Action {
    if (matches.length === 0) return 'LOG_ONLY';

    const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const severity of severityOrder) {
      if (matches.some((m) => m.severity === severity)) {
        return SEVERITY_ACTIONS[severity];
      }
    }
    return 'LOG_ONLY';
  }

  /**
   * Mask sensitive data for safe logging.
   * Shows first/last few characters, masks the middle.
   */
  private maskSensitive(text: string, severity: Severity): string {
    if (severity === 'CRITICAL') {
      // For critical data, mask aggressively — show only first 3 and last 2 chars
      if (text.length > 8) {
        return text.substring(0, 3) + '*'.repeat(text.length - 5) + text.substring(text.length - 2);
      }
      return '*'.repeat(text.length);
    }
    // For lower severity, return as-is (context is needed for review)
    return text;
  }
}
