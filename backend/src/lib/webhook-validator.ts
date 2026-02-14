/**
 * Webhook URL Validator
 * 
 * Protects against SSRF (Server-Side Request Forgery) attacks by validating
 * webhook URLs before they are stored or used.
 */

import { URL } from 'url';
import dns from 'dns/promises';

// Allowed webhook domains (whitelist approach for security)
const ALLOWED_DOMAINS = [
  'discord.com',
  'discordapp.com',
] as const;

// Blocked hostnames (localhost, loopback, etc.)
const BLOCKED_HOSTNAMES = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
  'host.docker.internal',
  'kubernetes.default',
  'metadata.google.internal',
];

// Private IP ranges (RFC 1918 + link-local + loopback)
const PRIVATE_IP_RANGES = [
  // 10.0.0.0/8
  { start: [10, 0, 0, 0], end: [10, 255, 255, 255] },
  // 172.16.0.0/12
  { start: [172, 16, 0, 0], end: [172, 31, 255, 255] },
  // 192.168.0.0/16
  { start: [192, 168, 0, 0], end: [192, 168, 255, 255] },
  // 169.254.0.0/16 (link-local / AWS metadata)
  { start: [169, 254, 0, 0], end: [169, 254, 255, 255] },
  // 127.0.0.0/8 (loopback)
  { start: [127, 0, 0, 0], end: [127, 255, 255, 255] },
];

/**
 * Check if an IPv4 address is in a private range
 */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Invalid IP format, treat as private for safety
  }

  for (const range of PRIVATE_IP_RANGES) {
    let inRange = true;
    for (let i = 0; i < 4; i++) {
      if ((parts[i] as number) < (range.start[i] as number) || (parts[i] as number) > (range.end[i] as number)) {
        inRange = false;
        break;
      }
    }
    if (inRange) return true;
  }

  return false;
}

/**
 * Check if a hostname is in the allowed list
 */
function isAllowedDomain(hostname: string): boolean {
  const normalizedHostname = hostname.toLowerCase();
  return ALLOWED_DOMAINS.some(domain => 
    normalizedHostname === domain || normalizedHostname.endsWith(`.${domain}`)
  );
}

interface WebhookValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate a webhook URL for SSRF protection
 * 
 * @param url - The webhook URL to validate
 * @param skipDnsCheck - Skip DNS resolution check (for testing)
 * @returns Validation result with error message if invalid
 */
export async function validateWebhookUrl(
  url: string,
  skipDnsCheck: boolean = false
): Promise<WebhookValidationResult> {
  try {
    const parsed = new URL(url);

    // 1. Protocol check - only HTTPS allowed in production
    if (parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: 'Webhook URL must use HTTPS protocol for security',
      };
    }

    // 2. Blocked hostname check
    const hostname = parsed.hostname.toLowerCase();
    if (BLOCKED_HOSTNAMES.includes(hostname)) {
      return {
        valid: false,
        error: 'Webhook URL cannot point to localhost or internal addresses',
      };
    }

    // 3. IP address format check (block direct IP access)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;
    if (ipv4Regex.test(hostname)) {
      if (isPrivateIP(hostname)) {
        return {
          valid: false,
          error: 'Webhook URL cannot point to private IP addresses',
        };
      }
    } else if (ipv6Regex.test(hostname)) {
      return {
        valid: false,
        error: 'Webhook URL must use a domain name, not an IP address',
      };
    }

    // 4. Domain allowlist check
    if (!isAllowedDomain(hostname)) {
      return {
        valid: false,
        error: 'Webhook URL must be from a Discord domain (discord.com, discordapp.com).',
      };
    }

    // 5. DNS resolution check (prevent DNS rebinding)
    if (!skipDnsCheck) {
      try {
        const addresses = await dns.resolve4(hostname);
        for (const ip of addresses) {
          if (isPrivateIP(ip)) {
            return {
              valid: false,
              error: 'Webhook URL resolves to a private IP address',
            };
          }
        }
      } catch {
        // DNS resolution failed — fail-closed for safety
        return {
          valid: false,
          error: 'Could not resolve webhook URL hostname. Please verify the URL and try again.',
        };
      }
    }

    // 6. Path validation (no suspicious paths)
    const suspiciousPaths = ['/admin', '/api/internal', '/.env', '/config'];
    if (suspiciousPaths.some(p => parsed.pathname.toLowerCase().includes(p))) {
      return {
        valid: false,
        error: 'Webhook URL contains suspicious path segments',
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      error: 'Invalid webhook URL format',
    };
  }
}

