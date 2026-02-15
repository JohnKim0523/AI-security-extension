import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { PoliciesService, DLPPolicy } from './policies.service';

@Controller('policies')
export class PoliciesController {
  constructor(private readonly policiesService: PoliciesService) {}

  /**
   * GET /api/policies
   * The extension calls this on startup to fetch DLP rules.
   */
  @Get()
  getAllPolicies() {
    return this.policiesService.getAllPolicies();
  }

  /**
   * GET /api/policies/:id
   */
  @Get(':id')
  getPolicy(@Param('id') id: string) {
    const policy = this.policiesService.getPolicy(id);
    if (!policy) {
      throw new HttpException('Policy not found', HttpStatus.NOT_FOUND);
    }
    return policy;
  }

  /**
   * POST /api/policies
   * Admin creates a new DLP policy.
   */
  @Post()
  createPolicy(@Body() body: Omit<DLPPolicy, 'id' | 'createdAt' | 'updatedAt'>) {
    return this.policiesService.createPolicy(body);
  }

  /**
   * PUT /api/policies/:id
   * Admin updates a DLP policy.
   */
  @Put(':id')
  updatePolicy(@Param('id') id: string, @Body() body: Partial<DLPPolicy>) {
    const updated = this.policiesService.updatePolicy(id, body);
    if (!updated) {
      throw new HttpException('Policy not found', HttpStatus.NOT_FOUND);
    }
    return updated;
  }

  /**
   * DELETE /api/policies/:id
   */
  @Delete(':id')
  deletePolicy(@Param('id') id: string) {
    const deleted = this.policiesService.deletePolicy(id);
    if (!deleted) {
      throw new HttpException('Policy not found', HttpStatus.NOT_FOUND);
    }
    return { deleted: true };
  }
}
