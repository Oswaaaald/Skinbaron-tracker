import { eq, and, count } from 'drizzle-orm';
import { passkeys } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { Passkey } from '../schema.js';

export class PasskeysRepository {
  constructor(private db: AppDatabase) {}

  async findByUserId(userId: number): Promise<Passkey[]> {
    return this.db.select().from(passkeys).where(eq(passkeys.user_id, userId));
  }

  async findByCredentialId(credentialId: string): Promise<Passkey | null> {
    const [row] = await this.db.select().from(passkeys)
      .where(eq(passkeys.credential_id, credentialId))
      .limit(1);
    return row ?? null;
  }

  async findById(id: number, userId: number): Promise<Passkey | null> {
    const [row] = await this.db.select().from(passkeys)
      .where(and(eq(passkeys.id, id), eq(passkeys.user_id, userId)))
      .limit(1);
    return row ?? null;
  }

  async create(data: {
    user_id: number;
    credential_id: string;
    public_key: string;
    counter: number;
    device_type: string;
    backed_up: boolean;
    transports?: string;
    name?: string;
  }): Promise<Passkey> {
    const [row] = await this.db.insert(passkeys).values(data).returning();
    return row as Passkey;
  }

  async updateCounter(credentialId: string, counter: number): Promise<void> {
    await this.db.update(passkeys)
      .set({ counter, last_used_at: new Date() })
      .where(eq(passkeys.credential_id, credentialId));
  }

  async rename(id: number, userId: number, name: string): Promise<Passkey | null> {
    const [row] = await this.db.update(passkeys)
      .set({ name })
      .where(and(eq(passkeys.id, id), eq(passkeys.user_id, userId)))
      .returning();
    return row ?? null;
  }

  async delete(id: number, userId: number): Promise<boolean> {
    const result = await this.db.delete(passkeys)
      .where(and(eq(passkeys.id, id), eq(passkeys.user_id, userId)))
      .returning({ id: passkeys.id });
    return result.length > 0;
  }

  async countByUserId(userId: number): Promise<number> {
    const [row] = await this.db.select({ value: count() })
      .from(passkeys)
      .where(eq(passkeys.user_id, userId));
    return row?.value ?? 0;
  }
}
