import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser, invalidateUserCache } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import {
  AdminUserParamsSchema,
  SanctionParamsSchema,
  RestrictUserSchema,
  UnrestrictUserSchema,
} from '../../database/schemas.js';

type RegisterAdminModerationRoutesOptions = {
  adminWriteRateLimit: {
    max: number;
    timeWindow: string;
    errorResponseBuilder: () => {
      statusCode: number;
      success: boolean;
      error: string;
      message: string;
    };
  };
};

export function registerAdminModerationRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminModerationRoutesOptions,
): void {
  // ==================== Moderation ====================

  /**
   * PATCH /api/admin/users/:id/restrict - Restrict a user (temporary or permanent)
   * Restricted users cannot log in or make API requests.
   * - temporary: user sees expiry date in their local timezone
   * - permanent: user sees "Your account has been permanently suspended"
   */
  fastify.patch('/users/:id/restrict', {
    config: { rateLimit: adminWriteRateLimit },
    schema: {
      description: 'Restrict a user account — temporary (with duration) or permanent (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'integer', minimum: 1 } } },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['restriction_type', 'reason'],
        properties: {
          restriction_type: { type: 'string', enum: ['temporary', 'permanent'] },
          reason: { type: 'string', minLength: 1, maxLength: 500 },
          duration_hours: { type: 'integer', minimum: 1, maximum: 8760, description: 'Required for temporary restrictions (max 1 year)' },
          ban_email: { type: 'boolean', description: 'Also ban the user email to prevent re-registration (permanent only)' },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const { restriction_type, reason, duration_hours, ban_email } = validateWithZod(RestrictUserSchema, request.body);
      const adminId = getAuthUser(request).id;

      if (id === adminId) throw Errors.forbidden('You cannot restrict your own account');

      const user = await store.users.findById(id);
      if (!user) throw Errors.notFound('User');
      if (user.is_super_admin) throw Errors.forbidden('Cannot moderate a super administrator');
      if (user.is_admin) {
        const currentAdmin = await store.users.findById(adminId);
        if (!currentAdmin?.is_super_admin) throw Errors.forbidden('Only super admins can restrict admins');
      }

      const admin = await store.users.findById(adminId);
      const adminUsername = admin?.username || 'Unknown';

      const expiresAt = restriction_type === 'temporary' && duration_hours
        ? new Date(Date.now() + duration_hours * 60 * 60 * 1000)
        : null;

      await store.users.update(id, {
        is_restricted: true,
        restriction_type,
        restriction_reason: reason,
        restriction_expires_at: expiresAt,
        restricted_at: new Date(),
        restricted_by_admin_id: adminId,
      });

      // Create sanction record
      await store.createSanction({
        user_id: id,
        admin_id: adminId,
        admin_username: adminUsername,
        action: 'restrict',
        restriction_type,
        reason,
        duration_hours: duration_hours || null,
        expires_at: expiresAt,
      });

      // Invalidate cache + revoke sessions + blacklist access tokens
      invalidateUserCache(id);
      const revokedJtis = await store.auth.revokeAllForUser(id);
      const accessExpiry = Date.now() + 15 * 60 * 1000;
      await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, id, accessExpiry, 'account_restricted')));

      // Ban email for permanent restrictions if requested
      if (restriction_type === 'permanent' && ban_email) {
        // Ban primary email
        await store.banEmail(user.email, reason, adminId);

        // Ban all OAuth provider emails
        const oauthAccounts = await store.oauth.findByUserId(id);
        for (const acc of oauthAccounts) {
          if (acc.provider_email && acc.provider_email !== user.email) {
            await store.banEmail(acc.provider_email, reason, adminId);
          }
        }
      }

      const durationLabel = restriction_type === 'permanent'
        ? 'permanently'
        : `for ${duration_hours}h (until ${expiresAt?.toISOString()})`;

      await store.audit.logAdminAction(adminId, 'restrict_user', id, `Restricted ${user.username} ${durationLabel} — ${reason}`);
      await store.audit.createLog(id, 'account_restricted', JSON.stringify({
        admin_id: adminId,
        admin_username: adminUsername,
        restriction_type,
        reason,
        duration_hours: duration_hours || null,
        expires_at: expiresAt,
        email_banned: ban_email || false,
      }), getClientIp(request), request.headers['user-agent']);

      return reply.status(200).send({
        success: true,
        message: `${user.username} has been restricted ${durationLabel}`,
        data: { is_restricted: true, restriction_type, restriction_expires_at: expiresAt },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Restrict user');
    }
  });

  /**
   * PATCH /api/admin/users/:id/unrestrict - Remove restriction from a user
   */
  fastify.patch('/users/:id/unrestrict', {
    config: { rateLimit: adminWriteRateLimit },
    schema: {
      description: 'Remove restriction from a user account (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'integer', minimum: 1 } } },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['reason'],
        properties: {
          reason: { type: 'string', minLength: 1, maxLength: 500 },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const { reason } = validateWithZod(UnrestrictUserSchema, request.body);
      const adminId = getAuthUser(request).id;

      const user = await store.users.findById(id);
      if (!user) throw Errors.notFound('User');
      if (!user.is_restricted) throw Errors.badRequest('This user is not currently restricted');

      // Protect admin targets: only super admins can unrestrict admin/super_admin users
      if (user.is_super_admin) throw Errors.forbidden('Cannot unrestrict a super administrator');
      if (user.is_admin) {
        const currentAdmin = await store.users.findById(adminId);
        if (!currentAdmin?.is_super_admin) throw Errors.forbidden('Only super admins can unrestrict admin accounts');
      }

      const admin = await store.users.findById(adminId);
      const adminUsername = admin?.username || 'Unknown';
      const wasType = user.restriction_type;

      await store.users.update(id, {
        is_restricted: false,
        restriction_type: null,
        restriction_reason: null,
        restriction_expires_at: null,
        restricted_at: null,
        restricted_by_admin_id: null,
      });

      // Create sanction record for unrestriction
      await store.createSanction({
        user_id: id,
        admin_id: adminId,
        admin_username: adminUsername,
        action: 'unrestrict',
        restriction_type: null,
        reason,
      });

      invalidateUserCache(id);

      // Unban email(s) if it was permanently restricted
      if (wasType === 'permanent') {
        await store.unbanEmail(user.email);

        // Also unban all OAuth provider emails
        const oauthAccounts = await store.oauth.findByUserId(id);
        for (const acc of oauthAccounts) {
          if (acc.provider_email && acc.provider_email !== user.email) {
            await store.unbanEmail(acc.provider_email);
          }
        }
      }

      await store.audit.logAdminAction(adminId, 'unrestrict_user', id, `Unrestricted ${user.username} — ${reason}`);
      await store.audit.createLog(id, 'account_unrestricted', JSON.stringify({
        admin_id: adminId,
        admin_username: adminUsername,
        reason,
        previous_restriction_type: wasType,
      }), getClientIp(request), request.headers['user-agent']);

      return reply.status(200).send({
        success: true,
        message: `${user.username} has been unrestricted`,
        data: { is_restricted: false },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Unrestrict user');
    }
  });

  /**
   * DELETE /api/admin/sanctions/:sanctionId - Delete a sanction from history (super admin only)
   * If the sanction is the currently active restriction, also unrestricts the user.
   */
  fastify.delete('/sanctions/:sanctionId', {
    config: { rateLimit: adminWriteRateLimit },
    schema: {
      description: 'Delete a sanction from history (super admin only). Unrestricts user if sanction is active.',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: { type: 'object', required: ['sanctionId'], properties: { sanctionId: { type: 'integer', minimum: 1 } } },
    },
  }, async (request, reply) => {
    try {
      const { sanctionId } = validateWithZod(SanctionParamsSchema, request.params);
      const adminId = getAuthUser(request).id;

      // Super admin only
      const admin = await store.users.findById(adminId);
      if (!admin?.is_super_admin) throw Errors.forbidden('Only super admins can delete sanctions');

      const sanction = await store.getSanctionById(sanctionId);
      if (!sanction) throw Errors.notFound('Sanction');

      const user = await store.users.findById(sanction.user_id);
      if (!user) throw Errors.notFound('User');

      // If this is the most recent "restrict" sanction and user is currently restricted, unrestrict them
      if (sanction.action === 'restrict' && user.is_restricted) {
        // Check if this is the sanction that caused the current restriction
        // (most recent restrict sanction for this user)
        const allSanctions = await store.getSanctionsByUserId(sanction.user_id);
        const latestRestrict = allSanctions.find(s => s.action === 'restrict');
        if (latestRestrict && latestRestrict.id === sanction.id) {
          await store.users.update(sanction.user_id, {
            is_restricted: false,
            restriction_type: null,
            restriction_reason: null,
            restriction_expires_at: null,
            restricted_at: null,
            restricted_by_admin_id: null,
          });
          invalidateUserCache(sanction.user_id);
        }
      }

      // Always unban emails when deleting a permanent restrict sanction,
      // regardless of current restriction status (the user may have been
      // unrestricted first, but email bans persist separately)
      if (sanction.action === 'restrict' && sanction.restriction_type === 'permanent') {
        await store.unbanEmail(user.email);

        const oauthAccounts = await store.oauth.findByUserId(sanction.user_id);
        for (const acc of oauthAccounts) {
          if (acc.provider_email && acc.provider_email !== user.email) {
            await store.unbanEmail(acc.provider_email);
          }
        }
      }

      await store.deleteSanction(sanctionId);

      await store.audit.logAdminAction(adminId, 'delete_sanction', sanction.user_id, `Deleted sanction #${sanctionId} (${sanction.action}) for ${user.username}`);
      await store.audit.createLog(sanction.user_id, 'sanction_deleted', JSON.stringify({
        sanction_id: sanctionId,
        action: sanction.action,
        restriction_type: sanction.restriction_type,
        reason: sanction.reason,
        deleted_by_admin_id: adminId,
        deleted_by_admin_username: admin.username,
      }), getClientIp(request), request.headers['user-agent']);

      return reply.status(200).send({
        success: true,
        message: 'Sanction deleted',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete sanction');
    }
  });
}
