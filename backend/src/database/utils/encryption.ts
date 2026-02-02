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
 * Derives a key from the encryption key using PBKDF2
 */
function getKey(salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(appConfig.ENCRYPTION_KEY, salt, PBKDF2_ITERATIONS, 32, 'sha512');
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

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * Hashes a token using SHA256
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}
