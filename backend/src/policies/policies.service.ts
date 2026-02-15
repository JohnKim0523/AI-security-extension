import { Injectable } from '@nestjs/common';

export interface PolicyRule {
  type: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  regex: string;
  description: string;
  enabled: boolean;
}

export interface DLPPolicy {
  id: string;
  name: string;
  enabled: boolean;
  rules: PolicyRule[];
  createdAt: number;
  updatedAt: number;
}

@Injectable()
export class PoliciesService {
  // In-memory store for MVP. Replace with database in production.
  private policies: DLPPolicy[] = [
    {
      id: 'default',
      name: 'Default DLP Policy',
      enabled: true,
      rules: [
        {
          type: 'SSN',
          category: 'PII',
          severity: 'CRITICAL',
          regex: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
          description: 'US Social Security Numbers',
          enabled: true,
        },
        {
          type: 'Credit Card',
          category: 'PII',
          severity: 'CRITICAL',
          regex: '\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{1,4}\\b',
          description: 'Payment card numbers (Visa, MC, Amex, Discover)',
          enabled: true,
        },
        {
          type: 'AWS Key',
          category: 'Credentials',
          severity: 'CRITICAL',
          regex: '(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
          description: 'AWS access key IDs',
          enabled: true,
        },
        {
          type: 'Private Key',
          category: 'Credentials',
          severity: 'CRITICAL',
          regex: '-----BEGIN\\s(?:RSA|EC|DSA|OPENSSH)?\\s?PRIVATE KEY-----',
          description: 'PEM-encoded private keys',
          enabled: true,
        },
        {
          type: 'API Key',
          category: 'Credentials',
          severity: 'CRITICAL',
          regex: '(?:api[_-]?key|apikey|api[_-]?token)\\s*[:=]\\s*[\'"]?[A-Za-z0-9_\\-]{20,}[\'"]?',
          description: 'Generic API keys and tokens',
          enabled: true,
        },
        {
          type: 'Internal IP',
          category: 'Infrastructure',
          severity: 'HIGH',
          regex: '\\b(?:10\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b',
          description: 'RFC 1918 private IP addresses',
          enabled: true,
        },
      ],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    },
  ];

  /**
   * Get all policies (the extension fetches these on startup).
   */
  getAllPolicies(): DLPPolicy[] {
    return this.policies;
  }

  /**
   * Get a single policy by ID.
   */
  getPolicy(id: string): DLPPolicy | undefined {
    return this.policies.find((p) => p.id === id);
  }

  /**
   * Create a new policy.
   */
  createPolicy(policy: Omit<DLPPolicy, 'id' | 'createdAt' | 'updatedAt'>): DLPPolicy {
    const newPolicy: DLPPolicy = {
      ...policy,
      id: crypto.randomUUID(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this.policies.push(newPolicy);
    return newPolicy;
  }

  /**
   * Update an existing policy.
   */
  updatePolicy(id: string, updates: Partial<DLPPolicy>): DLPPolicy | null {
    const index = this.policies.findIndex((p) => p.id === id);
    if (index === -1) return null;

    this.policies[index] = {
      ...this.policies[index],
      ...updates,
      id, // Don't allow ID change
      updatedAt: Date.now(),
    };
    return this.policies[index];
  }

  /**
   * Delete a policy.
   */
  deletePolicy(id: string): boolean {
    const index = this.policies.findIndex((p) => p.id === id);
    if (index === -1) return false;
    this.policies.splice(index, 1);
    return true;
  }
}
