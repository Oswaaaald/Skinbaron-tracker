import { eq, and } from 'drizzle-orm';
import { oauthAccounts } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { OAuthAccount } from '../schema.js';

export type OAuthProvider = 'google' | 'github' | 'discord';

export class OAuthRepository {
  constructor(private db: AppDatabase) {}

  /**
   * Find an OAuth account by provider + provider account ID
   */
  async findByProviderAccount(provider: OAuthProvider, providerAccountId: string): Promise<OAuthAccount | null> {
    const [account] = await this.db.select()
      .from(oauthAccounts)
      .where(and(
        eq(oauthAccounts.provider, provider),
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
   * Link an OAuth account to a user
   */
  async link(userId: number, provider: OAuthProvider, providerAccountId: string, providerEmail?: string): Promise<OAuthAccount> {
    const [account] = await this.db.insert(oauthAccounts)
      .values({
        user_id: userId,
        provider,
        provider_account_id: providerAccountId,
        provider_email: providerEmail ?? null,
      })
      .returning();
    if (!account) throw new Error('Failed to create OAuth account');
    return account;
  }

  /**
   * Unlink an OAuth account from a user
   */
  async unlink(userId: number, provider: OAuthProvider): Promise<boolean> {
    const result = await this.db.delete(oauthAccounts)
      .where(and(
        eq(oauthAccounts.user_id, userId),
        eq(oauthAccounts.provider, provider),
      ))
      .returning({ id: oauthAccounts.id });
    return result.length > 0;
  }
}
