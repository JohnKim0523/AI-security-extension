import { Controller, Post, Get, Body, Query } from '@nestjs/common';
import { LoggingService, SecurityEvent } from './logging.service';

@Controller('logging')
export class LoggingController {
  constructor(private readonly loggingService: LoggingService) {}

  /**
   * POST /api/logging/events
   * Receives security events from the browser extension.
   */
  @Post('events')
  ingestEvent(@Body() event: SecurityEvent) {
    return this.loggingService.ingestEvent(event);
  }

  /**
   * GET /api/logging/events
   * Retrieves security events with optional filters.
   */
  @Get('events')
  getEvents(
    @Query('type') type?: string,
    @Query('domain') domain?: string,
    @Query('action') action?: string,
    @Query('limit') limit?: string,
  ) {
    return this.loggingService.getEvents({
      type,
      domain,
      action,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  /**
   * GET /api/logging/stats
   * Returns aggregate stats for the admin dashboard.
   */
  @Get('stats')
  getStats() {
    return this.loggingService.getStats();
  }
}
