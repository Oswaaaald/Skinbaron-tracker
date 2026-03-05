import crypto from 'crypto';
import { store } from '../database/index.js';

/**
 * Generate a unique username from an OAuth display name.
 * Sanitizes to [a-zA-Z0-9_], truncates to 17 chars, and appends
 * a random suffix if the name is already taken.
 */
export async function generateUniqueUsername(displayName: string): Promise<string> {
  // Sanitize: keep only allowed characters
  let base = displayName.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 17);
  if (base.length < 3) base = 'user';

  // Try the base name first
  const existing = await store.users.findByUsername(base);
  if (!existing) return base;

  // Append random suffix
  for (let i = 0; i < 10; i++) {
    const suffix = crypto.randomInt(100, 999).toString();
    const candidate = `${base.slice(0, 17)}_${suffix}`;
    const taken = await store.users.findByUsername(candidate);
    if (!taken) return candidate;
  }

  // Fallback: fully random
  return `user_${crypto.randomBytes(4).toString('hex')}`;
}
