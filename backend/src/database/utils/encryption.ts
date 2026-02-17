import crypto from 'crypto';
import { appConfig } from '../../lib/config.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const TAG_POSITION = SALT_LENGTH + IV_LENGTH;
const ENCRYPTED_POSITION = TAG_POSITION + TAG_LENGTH;

// OWASP 2024+ recommendation: 600,000+ iterations for PBKDF2-SHA512
const PBKDF2_ITERATIONS = 600_000;

/**
 * LRU cache for PBKDF2 derived keys — avoids re-deriving 600K iterations
 * for the same salt when decrypting the same value multiple times (e.g.
 * webhook URLs loaded on every poll cycle).
 */
const KEY_CACHE_MAX = 100;
const keyCache = new Map<string, Buffer>();

/**
 * Derives a key from the encryption key using PBKDF2 (cached per salt)
 */
function getKey(salt: Buffer): Buffer {
  const saltHex = salt.toString('hex');
  const cached = keyCache.get(saltHex);
  if (cached) {
    // Move to end (LRU freshness)
    keyCache.delete(saltHex);
    keyCache.set(saltHex, cached);
    return cached;
  }

  const key = crypto.pbkdf2Sync(appConfig.ENCRYPTION_KEY, salt, PBKDF2_ITERATIONS, 32, 'sha512');

  // Evict oldest entry if full
  if (keyCache.size >= KEY_CACHE_MAX) {
    const oldest = keyCache.keys().next().value;
    if (oldest !== undefined) keyCache.delete(oldest);
  }
  keyCache.set(saltHex, key);
  return key;
}

/**
 * Encrypts data using AES-256-GCM
 * Format: salt(64) + iv(16) + tag(16) + encrypted_data
 */
export function encryptData(data: string): string {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getKey(salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

/**
 * Decrypts data encrypted with encryptData()
 */
export function decryptData(encryptedData: string): string {
  const buffer = Buffer.from(encryptedData, 'base64');

  const salt = buffer.subarray(0, SALT_LENGTH);
  const iv = buffer.subarray(SALT_LENGTH, TAG_POSITION);
  const tag = buffer.subarray(TAG_POSITION, ENCRYPTED_POSITION);
  const encrypted = buffer.subarray(ENCRYPTED_POSITION);

  const key = getKey(salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

/**
 * Hashes a token using SHA256
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ==================== Lightweight cookie encryption ====================
// Used for short-lived, non-persistent data (OAuth state, 2FA pending, etc.)
// No PBKDF2 — derives key via SHA-256 hash of ENCRYPTION_KEY for speed.
// PBKDF2 is reserved for at-rest data (webhook URLs, TOTP secrets).

/**
 * Encrypt a JSON-serialisable payload into a base64url cookie value.
 * Uses AES-256-GCM with a SHA-256-derived key (fast, safe for ephemeral data).
 */
export function encryptCookie(payload: string): string {
  const key = crypto.createHash('sha256').update(appConfig.ENCRYPTION_KEY).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

/**
 * Decrypt a base64url cookie value produced by encryptCookie().
 */
export function decryptCookie(cookieValue: string): string {
  const buf = Buffer.from(cookieValue, 'base64url');
  const key = crypto.createHash('sha256').update(appConfig.ENCRYPTION_KEY).digest();
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}
