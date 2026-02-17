import { Severity } from './types';

// =============================================================================
// DLP DETECTION PATTERNS
// Pulled directly from llm_dlp_target_list.docx - Appendix regex patterns
// plus additional patterns from the data classification tables
// =============================================================================

export interface DetectionPattern {
  name: string;
  category: string;
  severity: Severity;
  regex: RegExp;
  description: string;
  validate?: (match: string) => boolean;  // Optional secondary validation
}

// --- TARGET AI/LLM DOMAINS ---
// The DLP agent monitors traffic to these domains (from target list doc)
export const AI_TOOL_DOMAINS: Record<string, string> = {
  'chat.openai.com': 'ChatGPT',
  'chatgpt.com': 'ChatGPT',
  'api.openai.com': 'OpenAI API',
  'platform.openai.com': 'OpenAI Platform',
  'claude.ai': 'Claude',
  'api.anthropic.com': 'Anthropic API',
  'console.anthropic.com': 'Anthropic Console',
  'gemini.google.com': 'Google Gemini',
  'aistudio.google.com': 'Google AI Studio',
  'copilot.microsoft.com': 'Microsoft Copilot',
  'perplexity.ai': 'Perplexity',
  'api.perplexity.ai': 'Perplexity API',
  'chat.mistral.ai': 'Mistral',
  'api.mistral.ai': 'Mistral API',
  'grok.x.ai': 'Grok',
  'api.x.ai': 'xAI API',
  'chat.deepseek.com': 'DeepSeek',
  'api.deepseek.com': 'DeepSeek API',
  'huggingface.co': 'Hugging Face',
  'coral.cohere.com': 'Cohere',
  'cursor.sh': 'Cursor',
  'codeium.com': 'Codeium',
  'tabnine.com': 'Tabnine',
};

// --- Luhn checksum validator for credit card numbers ---
function luhnCheck(num: string): boolean {
  const digits = num.replace(/[\s-]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// --- SSN area number validation (basic) ---
function validateSSN(ssn: string): boolean {
  const cleaned = ssn.replace(/[-\s]/g, '');
  const area = parseInt(cleaned.substring(0, 3), 10);
  // Area numbers 000, 666, and 900-999 are invalid
  if (area === 0 || area === 666 || area >= 900) return false;
  const group = parseInt(cleaned.substring(3, 5), 10);
  const serial = parseInt(cleaned.substring(5, 9), 10);
  return group !== 0 && serial !== 0;
}

// =============================================================================
// DETECTION PATTERNS BY CATEGORY
// =============================================================================

export const DETECTION_PATTERNS: DetectionPattern[] = [
  // ─── PII: CRITICAL ─────────────────────────────────────────────
  {
    name: 'Social Security Number',
    category: 'PII',
    severity: 'CRITICAL',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    description: 'US Social Security Number (XXX-XX-XXXX)',
    validate: validateSSN,
  },
  {
    name: 'SSN (no dashes)',
    category: 'PII',
    severity: 'CRITICAL',
    regex: /\b(?:ssn|social\s*security)\s*(?:number|#|no)?[\s:]*(\d{9})\b/gi,
    description: 'SSN without dashes, with context keywords',
  },
  {
    name: 'Credit Card Number',
    category: 'PII',
    severity: 'CRITICAL',
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b/g,
    description: 'Visa, Mastercard, Amex, Discover card numbers',
    validate: (match) => luhnCheck(match),
  },
  {
    name: 'Government ID / Passport',
    category: 'PII',
    severity: 'CRITICAL',
    regex: /\b(?:passport|driver'?s?\s*license|DL)\s*(?:#|no|number)?[\s:]*[A-Z0-9]{6,12}\b/gi,
    description: 'Passport or drivers license numbers with context',
  },

  // ─── PII: HIGH ─────────────────────────────────────────────────
  {
    name: 'Bank Account + Routing',
    category: 'PII',
    severity: 'CRITICAL',
    regex: /\b(?:routing|account)\s*(?:#|no|number)?[\s:]*\d{8,17}\b/gi,
    description: 'Bank account or routing numbers with context',
  },
  {
    name: 'Date of Birth',
    category: 'PII',
    severity: 'HIGH',
    regex: /\b(?:dob|date\s*of\s*birth|born|birthday)[\s:]*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/gi,
    description: 'Date of birth with context keywords',
  },
  {
    name: 'Phone Number',
    category: 'PII',
    severity: 'MEDIUM',
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    description: 'US phone numbers in various formats',
  },
  {
    name: 'Email Address (Internal)',
    category: 'PII',
    severity: 'MEDIUM',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    description: 'Email addresses',
  },

  // ─── CREDENTIALS & SECRETS: CRITICAL ───────────────────────────
  {
    name: 'AWS Access Key',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    description: 'AWS access key IDs',
  },
  {
    name: 'AWS Secret Key',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?[A-Za-z0-9\/+=]{40}['"]?/gi,
    description: 'AWS secret access keys',
  },
  {
    name: 'GitHub Token',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    description: 'GitHub personal access tokens or fine-grained tokens',
  },
  {
    name: 'Generic API Key',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/gi,
    description: 'Generic API keys and tokens with context',
  },
  {
    name: 'Private Key (PEM)',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)?\s?PRIVATE KEY-----/g,
    description: 'PEM-encoded private keys',
  },
  {
    name: 'JWT Token',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
    description: 'JSON Web Tokens (3-part base64url)',
  },
  {
    name: 'Slack Token',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /xox[bpoas]-[0-9a-zA-Z-]{10,}/g,
    description: 'Slack bot, user, or app tokens',
  },
  {
    name: 'Connection String',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+/gi,
    description: 'Database connection URIs',
  },
  {
    name: 'Stripe Key',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/g,
    description: 'Stripe API keys (live or test)',
  },
  {
    name: 'Password in Context',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?[^\s'"]{6,}['"]?/gi,
    description: 'Passwords with context keywords',
  },
  {
    name: 'OAuth / Bearer Token',
    category: 'Credentials',
    severity: 'CRITICAL',
    regex: /(?:bearer|authorization)\s*[:=]?\s*['"]?[A-Za-z0-9_\-.]{20,}['"]?/gi,
    description: 'OAuth bearer tokens',
  },

  // ─── INFRASTRUCTURE: HIGH ──────────────────────────────────────
  {
    name: 'Internal IP Address',
    category: 'Infrastructure',
    severity: 'HIGH',
    regex: /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g,
    description: 'RFC 1918 private IP addresses',
  },
  {
    name: 'Cloud Resource ARN',
    category: 'Infrastructure',
    severity: 'HIGH',
    regex: /arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_\/:.]+/g,
    description: 'AWS ARN resource identifiers',
  },

  // ─── HEALTH DATA (PHI): CRITICAL ──────────────────────────────
  {
    name: 'Medical Record Number',
    category: 'PHI',
    severity: 'CRITICAL',
    regex: /\b(?:MRN|medical\s*record|patient\s*id)\s*(?:#|no|number)?[\s:]*[A-Z0-9]{6,15}\b/gi,
    description: 'Medical record numbers with context',
  },
  {
    name: 'ICD-10 Diagnosis Code',
    category: 'PHI',
    severity: 'HIGH',
    regex: /\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/g,
    description: 'ICD-10 medical diagnosis codes',
  },

  // ─── CORPORATE / BUSINESS: HIGH ────────────────────────────────
  {
    name: 'Confidential Document Marker',
    category: 'Corporate',
    severity: 'HIGH',
    regex: /\b(?:CONFIDENTIAL|INTERNAL\s*ONLY|PROPRIETARY|NOT\s*FOR\s*DISTRIBUTION|NDA|TRADE\s*SECRET)\b/gi,
    description: 'Document classification markers',
  },
  {
    name: 'Source Code (Function Defs)',
    category: 'Corporate',
    severity: 'HIGH',
    regex: /(?:function\s+\w+\s*\(|def\s+\w+\s*\(|class\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(|import\s+{[^}]+}\s+from)/g,
    description: 'Code patterns — function definitions, imports, classes',
  },
  {
    name: 'SQL Query',
    category: 'Corporate',
    severity: 'CRITICAL',
    regex: /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|UPDATE\s+\w+\s+SET)\b/gi,
    description: 'SQL database queries and schema operations',
  },

  // ─── LEGAL: CRITICAL ──────────────────────────────────────────
  {
    name: 'Attorney-Client Privilege',
    category: 'Legal',
    severity: 'CRITICAL',
    regex: /\b(?:attorney[\s-]client\s*privilege|privileged\s*(?:and|&)\s*confidential|work\s*product\s*doctrine|legal\s*privilege)\b/gi,
    description: 'Attorney-client privileged communication markers',
  },
];

// =============================================================================
// ENCODING EVASION DETECTION
// Pre-processing decode pipeline to catch base64, URL-encoded, hex, and
// Unicode escape evasion attempts before running DLP regex patterns.
// =============================================================================

const BASE64_REGEX = /[A-Za-z0-9+/]{20,}={0,2}/g;
const URL_ENCODED_REGEX = /(?:%[0-9A-Fa-f]{2}){4,}/g;
const HEX_REGEX = /(?:\\x[0-9a-fA-F]{2}){4,}/g;
const UNICODE_REGEX = /(?:\\u[0-9a-fA-F]{4}){2,}/g;

/**
 * Attempt to decode a base64 string. Returns null if invalid.
 */
function tryBase64Decode(encoded: string): string | null {
  try {
    const decoded = atob(encoded);
    // Validate that the decoded string contains printable characters
    if (/[\x20-\x7E]{4,}/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Attempt to decode URL-encoded sequences.
 */
function tryURLDecode(encoded: string): string | null {
  try {
    const decoded = decodeURIComponent(encoded);
    if (decoded !== encoded) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode hex escape sequences like \x41\x42\x43
 */
function tryHexDecode(encoded: string): string | null {
  try {
    const decoded = encoded.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    if (decoded !== encoded) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode Unicode escape sequences like \u0041\u0042
 */
function tryUnicodeDecode(encoded: string): string | null {
  try {
    const decoded = encoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, code) =>
      String.fromCharCode(parseInt(code, 16))
    );
    if (decoded !== encoded) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Run the decode pipeline on input text. Returns an array of decoded strings
 * (may be empty if no encodings detected). Does NOT include the original text.
 */
export function decodeEvasions(text: string): string[] {
  const decoded: string[] = [];

  // Base64 detection
  BASE64_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = BASE64_REGEX.exec(text)) !== null) {
    const result = tryBase64Decode(match[0]);
    if (result) decoded.push(result);
  }

  // URL-encoded detection
  URL_ENCODED_REGEX.lastIndex = 0;
  while ((match = URL_ENCODED_REGEX.exec(text)) !== null) {
    const result = tryURLDecode(match[0]);
    if (result) decoded.push(result);
  }

  // Hex escape detection
  HEX_REGEX.lastIndex = 0;
  while ((match = HEX_REGEX.exec(text)) !== null) {
    const result = tryHexDecode(match[0]);
    if (result) decoded.push(result);
  }

  // Unicode escape detection
  UNICODE_REGEX.lastIndex = 0;
  while ((match = UNICODE_REGEX.exec(text)) !== null) {
    const result = tryUnicodeDecode(match[0]);
    if (result) decoded.push(result);
  }

  return decoded;
}

// Sensitive file extensions that should be blocked on upload to AI tools
export const SENSITIVE_FILE_EXTENSIONS = [
  '.env', '.pem', '.key', '.csv', '.sql', '.json', '.xlsx',
  '.p12', '.pfx', '.keystore', '.jks', '.credentials',
];

// Text-based file extensions that can be read and scanned
export const SCANNABLE_FILE_EXTENSIONS = [
  '.txt', '.csv', '.json', '.env', '.sql', '.md', '.log',
  '.yml', '.yaml', '.xml', '.conf', '.cfg', '.ini', '.properties',
];

// Sensitive file types for download monitoring
export const SENSITIVE_DOWNLOAD_EXTENSIONS = [
  '.py', '.js', '.ts', '.sql', '.env', '.key', '.pem',
  '.csv', '.json', '.xlsx', '.zip', '.tar', '.gz',
];

// Helper: Check if a domain is a known AI tool
export function getAIToolName(hostname: string): string | null {
  // Check exact match first
  if (AI_TOOL_DOMAINS[hostname]) return AI_TOOL_DOMAINS[hostname];
  // Check subdomain match
  for (const [domain, name] of Object.entries(AI_TOOL_DOMAINS)) {
    if (hostname.endsWith('.' + domain) || hostname === domain) return name;
  }
  return null;
}
