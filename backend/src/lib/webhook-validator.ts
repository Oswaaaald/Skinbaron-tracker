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
  // Discord
  'discord.com',
  'discordapp.com',
  'discord.gg',
  // Slack
  'slack.com',
  'hooks.slack.com',
  // Microsoft Teams
  'webhook.office.com',
  'outlook.office.com',
  // Generic (for testing or self-hosted)
  // Note: Generic webhooks are validated but allowed to any HTTPS URL
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
      const part = parts[i];
      const rangeStart = range.start[i];
      const rangeEnd = range.end[i];
      if (part === undefined || rangeStart === undefined || rangeEnd === undefined || part < rangeStart || part > rangeEnd) {
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
function isAllowedDomain(hostname: string, webhookType: string): boolean {
  // Generic webhooks are allowed to any non-private HTTPS URL
  if (webhookType === 'generic') {
    return true;
  }

  const normalizedHostname = hostname.toLowerCase();
  return ALLOWED_DOMAINS.some(domain => 
    normalizedHostname === domain || normalizedHostname.endsWith(`.${domain}`)
  );
}

export interface WebhookValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate a webhook URL for SSRF protection
 * 
 * @param url - The webhook URL to validate
 * @param webhookType - The type of webhook (discord, slack, teams, generic)
 * @param skipDnsCheck - Skip DNS resolution check (for testing)
 * @returns Validation result with error message if invalid
 */
export async function validateWebhookUrl(
  url: string,
  webhookType: string = 'generic',
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
    if (!isAllowedDomain(hostname, webhookType)) {
      return {
        valid: false,
        error: `Webhook URL must be from an allowed domain for ${webhookType} webhooks. Allowed: Discord, Slack, Microsoft Teams, or use "generic" type for custom webhooks.`,
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
        // DNS resolution failed - could be temporary, allow but log
        // In production, you might want to be stricter here
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

/**
 * Synchronous version for quick validation (without DNS check)
 */
export function validateWebhookUrlSync(
  url: string,
  webhookType: string = 'generic'
): WebhookValidationResult {
  try {
    const parsed = new URL(url);

    if (parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: 'Webhook URL must use HTTPS protocol for security',
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    if (BLOCKED_HOSTNAMES.includes(hostname)) {
      return {
        valid: false,
        error: 'Webhook URL cannot point to localhost or internal addresses',
      };
    }

    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname) && isPrivateIP(hostname)) {
      return {
        valid: false,
        error: 'Webhook URL cannot point to private IP addresses',
      };
    }

    if (!isAllowedDomain(hostname, webhookType)) {
      return {
        valid: false,
        error: `Webhook URL must be from an allowed domain for ${webhookType} webhooks`,
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
