import type Database from 'better-sqlite3';
import type { UserWebhook, CreateUserWebhook, WebhookRow } from '../schemas.js';
import { CreateUserWebhookSchema } from '../schemas.js';
import { rowToWebhook } from '../utils/converters.js';
import { encryptData } from '../utils/encryption.js';

export class WebhooksRepository {
  constructor(private db: Database.Database) {}

  create(userId: number, webhook: CreateUserWebhook): UserWebhook {
    const validated = CreateUserWebhookSchema.parse(webhook);
    const encryptedUrl = encryptData(validated.webhook_url);
    
    const stmt = this.db.prepare(`
      INSERT INTO user_webhooks (user_id, name, webhook_url_encrypted, webhook_type, is_active)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      userId,
      validated.name,
      encryptedUrl,
      validated.webhook_type,
      validated.is_active ? 1 : 0
    );

    return this.findById(result.lastInsertRowid as number)!;
  }

  findById(id: number, decrypt: boolean = false): UserWebhook | null {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE id = ?');
    const row = stmt.get(id) as WebhookRow | undefined;
    if (!row) return null;
    return rowToWebhook(row, decrypt);
  }

  findByUserId(userId: number, decrypt: boolean = false): UserWebhook[] {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE user_id = ? ORDER BY created_at DESC');
    const rows = stmt.all(userId) as WebhookRow[];
    return rows.map(row => rowToWebhook(row, decrypt));
  }

  findByIds(ids: number[], decrypt: boolean = false): UserWebhook[] {
    if (ids.length === 0) return [];
    const placeholders = ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`SELECT * FROM user_webhooks WHERE id IN (${placeholders})`);
    const rows = stmt.all(...ids) as WebhookRow[];
    return rows.map(row => rowToWebhook(row, decrypt));
  }

  update(id: number, userId: number, updates: Partial<CreateUserWebhook>): UserWebhook | null {
    const validatedUpdates = CreateUserWebhookSchema.partial().parse(updates);
    
    const fields: string[] = [];
    const values: (string | number)[] = [];

    if (validatedUpdates.name) {
      fields.push('name = ?');
      values.push(validatedUpdates.name);
    }

    if (validatedUpdates.webhook_url) {
      fields.push('webhook_url_encrypted = ?');
      values.push(encryptData(validatedUpdates.webhook_url));
    }

    if (validatedUpdates.webhook_type) {
      fields.push('webhook_type = ?');
      values.push(validatedUpdates.webhook_type);
    }

    if (validatedUpdates.is_active !== undefined) {
      fields.push('is_active = ?');
      values.push(validatedUpdates.is_active ? 1 : 0);
    }

    if (fields.length === 0) {
      return this.findById(id);
    }

    fields.push('updated_at = CURRENT_TIMESTAMP');
    const setClause = fields.join(', ');
    
    const stmt = this.db.prepare(`UPDATE user_webhooks SET ${setClause} WHERE id = ? AND user_id = ?`);
    const result = stmt.run(...values, id, userId);
    
    if (result.changes === 0) {
      return null;
    }
    
    return this.findById(id)!;
  }

  delete(id: number, userId: number): boolean {
    const stmt = this.db.prepare('DELETE FROM user_webhooks WHERE id = ? AND user_id = ?');
    const result = stmt.run(id, userId);
    return result.changes > 0;
  }

  // Batch operations
  enableBatch(webhookIds: number[], userId: number): number {
    if (webhookIds.length === 0) return 0;
    const placeholders = webhookIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`UPDATE user_webhooks SET is_active = 1 WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...webhookIds, userId);
    return result.changes;
  }

  disableBatch(webhookIds: number[], userId: number): number {
    if (webhookIds.length === 0) return 0;
    const placeholders = webhookIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`UPDATE user_webhooks SET is_active = 0 WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...webhookIds, userId);
    return result.changes;
  }

  deleteBatch(webhookIds: number[], userId: number): number {
    if (webhookIds.length === 0) return 0;
    const placeholders = webhookIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`DELETE FROM user_webhooks WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...webhookIds, userId);
    return result.changes;
  }
}
