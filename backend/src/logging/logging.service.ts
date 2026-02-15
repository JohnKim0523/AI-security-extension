import { Injectable } from '@nestjs/common';

// Matches the SecurityEvent type from the extension
export interface SecurityEvent {
  id: string;
  type: 'DLP_VIOLATION' | 'AI_TOOL_ACCESS' | 'CLIPBOARD_PASTE' | 'FILE_UPLOAD';
  matches: any[];
  url: string;
  domain: string;
  action: string;
  userAgent: string;
  timestamp: number;
}

export interface EventStats {
  totalEvents: number;
  totalBlocked: number;
  totalWarnings: number;
  topDomains: Record<string, number>;
  topCategories: Record<string, number>;
  recentEvents: SecurityEvent[];
}

@Injectable()
export class LoggingService {
  // In-memory store for MVP. Replace with database (DynamoDB, Postgres, etc.) in production.
  private events: SecurityEvent[] = [];

  /**
   * Store a security event from the browser extension.
   */
  ingestEvent(event: SecurityEvent): { received: boolean; id: string } {
    this.events.push(event);

    // Keep last 10,000 events in memory
    if (this.events.length > 10000) {
      this.events = this.events.slice(-10000);
    }

    console.log(
      `[EVENT] ${event.type} | ${event.domain} | ${event.action} | ${event.matches.length} matches`,
    );

    return { received: true, id: event.id };
  }

  /**
   * Get all events, with optional filters.
   */
  getEvents(filters?: {
    type?: string;
    domain?: string;
    action?: string;
    limit?: number;
  }): SecurityEvent[] {
    let filtered = [...this.events];

    if (filters?.type) {
      filtered = filtered.filter((e) => e.type === filters.type);
    }
    if (filters?.domain) {
      filtered = filtered.filter((e) => e.domain === filters.domain);
    }
    if (filters?.action) {
      filtered = filtered.filter((e) => e.action === filters.action);
    }

    // Most recent first
    filtered.sort((a, b) => b.timestamp - a.timestamp);

    const limit = filters?.limit || 100;
    return filtered.slice(0, limit);
  }

  /**
   * Get aggregate stats for the dashboard.
   */
  getStats(): EventStats {
    const topDomains: Record<string, number> = {};
    const topCategories: Record<string, number> = {};
    let totalBlocked = 0;
    let totalWarnings = 0;

    for (const event of this.events) {
      // Count domains
      topDomains[event.domain] = (topDomains[event.domain] || 0) + 1;

      // Count categories from matches
      for (const match of event.matches) {
        const cat = match.category || 'Unknown';
        topCategories[cat] = (topCategories[cat] || 0) + 1;
      }

      // Count actions
      if (event.action === 'BLOCK_ALERT' || event.action === 'BLOCK_LOG') {
        totalBlocked++;
      } else if (event.action === 'WARN_LOG') {
        totalWarnings++;
      }
    }

    return {
      totalEvents: this.events.length,
      totalBlocked,
      totalWarnings,
      topDomains,
      topCategories,
      recentEvents: this.events.slice(-20).reverse(),
    };
  }
}
