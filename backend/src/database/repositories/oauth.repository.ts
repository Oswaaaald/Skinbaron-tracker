import { eq, and, sql } from 'drizzle-orm';
import { oauthAccounts } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { OAuthAccount } from '../schema.js';

export type OAuthProvider = 'google' | 'github' | 'discord';

export class OAuthRepository {
  constructor(private db: AppDatabase) {}

  /**
   * Find an OAuth account by provider + provider account ID
   */
  async findByProviderAccount(provider: string, providerAccountId: string): Promise<OAuthAccount | null> {
    const [account] = await this.db.select()
      .from(oauthAccounts)
      .where(and(
        eq(oauthAccounts.provider, provider as OAuthProvider),
        eq(oauthAccounts.provider_account_id, providerAccountId),
      ))
      .limit(1);
    return account ?? null;
  }

  /**
   * Find all OAuth accounts for a user
   */
  async findByUserId(userId: number): Promise<OAuthAccount[]> {
    return this.db.select()
      .from(oauthAccounts)
      .where(eq(oauthAccounts.user_id, userId));
  }

  /**
   * Check if an email is used as a provider_email by any OTHER user
   */
  async findByProviderEmail(email: string, excludeUserId?: number): Promise<OAuthAccount | null> {
    const conditions = [eq(oauthAccounts.provider_email, email)];
    if (excludeUserId !== undefined) {
      conditions.push(sql`${oauthAccounts.user_id} != ${excludeUserId}`);
    }
    const [account] = await this.db.select()
      .from(oauthAccounts)
      .where(and(...conditions))
      .limit(1);
    return account ?? null;
  }

  /**
   * Link an OAuth account to a user
   */
  async link(userId: number, provider: string, providerAccountId: string, providerEmail?: string): Promise<OAuthAccount> {
    const [account] = await this.db.insert(oauthAccounts)
      .values({
        user_id: userId,
        provider: provider as OAuthProvider,
        provider_account_id: providerAccountId,
        provider_email: providerEmail ?? null,
      })
      .returning();
    if (!account) throw new Error('Failed to create OAuth account');
    return account;
  }

  /**
   * Update the stored provider_email for an existing OAuth account.
   * Called when a returning user's email on the provider has changed.
   */
  async updateProviderEmail(provider: string, providerAccountId: string, newEmail: string): Promise<void> {
    await this.db.update(oauthAccounts)
      .set({ provider_email: newEmail })
      .where(and(
        eq(oauthAccounts.provider, provider as OAuthProvider),
        eq(oauthAccounts.provider_account_id, providerAccountId),
      ));
  }

  /**
   * Unlink an OAuth account from a user
   */
  async unlink(userId: number, provider: string): Promise<boolean> {
    const result = await this.db.delete(oauthAccounts)
      .where(and(
        eq(oauthAccounts.user_id, userId),
        eq(oauthAccounts.provider, provider as OAuthProvider),
      ))
      .returning({ id: oauthAccounts.id });
    return result.length > 0;
  }
}
