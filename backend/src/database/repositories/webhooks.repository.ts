import { eq, and, count, inArray, getTableColumns } from 'drizzle-orm';
import { userWebhooks, ruleWebhooks } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { UserWebhook } from '../schema.js';
import { encryptData, decryptData } from '../utils/encryption.js';

interface WebhookInput {
  name: string;
  webhook_url: string;
  webhook_type?: 'discord';
  notification_style?: 'compact' | 'detailed';
  is_active?: boolean;
}

export class WebhooksRepository {
  constructor(private db: AppDatabase) {}

  private withDecryptedUrl(webhook: typeof userWebhooks.$inferSelect): UserWebhook {
    return {
      ...webhook,
      webhook_url: decryptData(webhook.webhook_url_encrypted),
    };
  }

  async findById(id: number): Promise<UserWebhook | null> {
    const [webhook] = await this.db.select().from(userWebhooks).where(eq(userWebhooks.id, id)).limit(1);
    return webhook ?? null;
  }

  async findByUserId(userId: number, decrypt = false): Promise<UserWebhook[]> {
    const webhooks = await this.db.select()
      .from(userWebhooks)
      .where(eq(userWebhooks.user_id, userId))
      .orderBy(userWebhooks.created_at);

    if (decrypt) {
      return webhooks.map(w => this.withDecryptedUrl(w));
    }
    return webhooks;
  }

  async create(userId: number, data: WebhookInput): Promise<UserWebhook> {
    const [webhook] = await this.db.insert(userWebhooks).values({
      user_id: userId,
      name: data.name,
      webhook_url_encrypted: encryptData(data.webhook_url),
      webhook_type: data.webhook_type ?? 'discord',
      notification_style: data.notification_style ?? 'compact',
      is_active: data.is_active ?? true,
    }).returning();
    return webhook!;
  }

  async update(id: number, userId: number, data: Partial<WebhookInput>): Promise<UserWebhook | null> {
    const setValues: Record<string, unknown> = { updated_at: new Date() };

    if (data.name !== undefined) setValues['name'] = data.name;
    if (data.webhook_url !== undefined) setValues['webhook_url_encrypted'] = encryptData(data.webhook_url);
    if (data.webhook_type !== undefined) setValues['webhook_type'] = data.webhook_type;
    if (data.notification_style !== undefined) setValues['notification_style'] = data.notification_style;
    if (data.is_active !== undefined) setValues['is_active'] = data.is_active;

    const [webhook] = await this.db.update(userWebhooks)
      .set(setValues)
      .where(and(eq(userWebhooks.id, id), eq(userWebhooks.user_id, userId)))
      .returning();

    return webhook ?? null;
  }

  async delete(id: number, userId: number): Promise<boolean> {
    const result = await this.db.delete(userWebhooks)
      .where(and(eq(userWebhooks.id, id), eq(userWebhooks.user_id, userId)))
      .returning({ id: userWebhooks.id });
    return result.length > 0;
  }

  async enableBatch(ids: number[], userId: number): Promise<number> {
    if (ids.length === 0) return 0;
    const result = await this.db.update(userWebhooks)
      .set({ is_active: true, updated_at: new Date() })
      .where(and(inArray(userWebhooks.id, ids), eq(userWebhooks.user_id, userId)))
      .returning({ id: userWebhooks.id });
    return result.length;
  }

  async disableBatch(ids: number[], userId: number): Promise<number> {
    if (ids.length === 0) return 0;
    const result = await this.db.update(userWebhooks)
      .set({ is_active: false, updated_at: new Date() })
      .where(and(inArray(userWebhooks.id, ids), eq(userWebhooks.user_id, userId)))
      .returning({ id: userWebhooks.id });
    return result.length;
  }

  async deleteBatch(ids: number[], userId: number): Promise<number> {
    if (ids.length === 0) return 0;
    // Clean up junction table entries first
    if (ids.length > 0) {
      await this.db.delete(ruleWebhooks).where(inArray(ruleWebhooks.webhook_id, ids));
    }
    const result = await this.db.delete(userWebhooks)
      .where(and(inArray(userWebhooks.id, ids), eq(userWebhooks.user_id, userId)))
      .returning({ id: userWebhooks.id });
    return result.length;
  }

  async count(userId: number): Promise<number> {
    const [result] = await this.db.select({ value: count() })
      .from(userWebhooks)
      .where(eq(userWebhooks.user_id, userId));
    return result?.value ?? 0;
  }

  async getRuleWebhooksForNotification(ruleId: number): Promise<UserWebhook[]> {
    const webhookCols = getTableColumns(userWebhooks);
    const result = await this.db.select(webhookCols)
      .from(ruleWebhooks)
      .innerJoin(userWebhooks, eq(ruleWebhooks.webhook_id, userWebhooks.id))
      .where(and(
        eq(ruleWebhooks.rule_id, ruleId),
        eq(userWebhooks.is_active, true)
      ));

    return result.map(w => this.withDecryptedUrl(w));
  }
}
