import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import {
  getClientIp,
  getAuthUser,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  clearAuthCookies,
} from '../../lib/middleware.js';
import { deleteAvatarFile } from '../../lib/avatar.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { DeleteAccountSchema } from '../../database/schemas.js';

type RateLimitConfig = {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};

type RegisterUserAccountRoutesOptions = {
  sensitiveOperationRateLimit: RateLimitConfig;
  heavyOperationRateLimit: RateLimitConfig;
};

export function registerUserAccountRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit, heavyOperationRateLimit }: RegisterUserAccountRoutesOptions,
): void {
  /**
   * GET /api/user/data-export - GDPR data export (Art. 20 data portability)
   */
  fastify.get('/data-export', {
    config: {
      rateLimit: heavyOperationRateLimit,
    },
    schema: {
      description: 'Export all personal data (GDPR Art. 20)',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);

      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Collect all user data (no limits — full GDPR export)
      const rules = await store.rules.findByUserId(userId);
      const webhooks = await store.webhooks.findByUserId(userId, false); // Don't decrypt URLs
      const alerts = await store.alerts.findByUserId(userId, 0, 0); // limit=0 -> all alerts
      const auditLogs = await store.audit.getLogsByUserId(userId, 0); // limit=0 -> all logs
      const oauthAccounts = await store.oauth.findByUserId(userId);
      const passkeys = await store.passkeys.findByUserId(userId);
      const sanctionsHistory = await store.getSanctionsByUserId(userId, 0); // limit=0 -> all sanctions

      const exportData = {
        profile: {
          id: user.id,
          username: user.username,
          email: user.email,
          is_admin: user.is_admin,
          is_approved: user.is_approved,
          two_factor_enabled: user.totp_enabled,
          is_super_admin: user.is_super_admin,
          is_restricted: user.is_restricted,
          restriction_type: user.restriction_type,
          restriction_reason: user.restriction_reason,
          restriction_expires_at: user.restriction_expires_at,
          restricted_at: user.restricted_at,
          has_custom_avatar: !!user.avatar_filename,
          use_gravatar: user.use_gravatar,
          tos_accepted_at: user.tos_accepted_at,
          created_at: user.created_at,
          updated_at: user.updated_at,
        },
        oauth_accounts: oauthAccounts.map(a => ({
          provider: a.provider,
          provider_email: a.provider_email,
          created_at: a.created_at,
        })),
        rules: rules.map(r => ({
          id: r.id,
          search_item: r.search_item,
          min_price: r.min_price,
          max_price: r.max_price,
          min_wear: r.min_wear,
          max_wear: r.max_wear,
          stattrak_filter: r.stattrak_filter,
          souvenir_filter: r.souvenir_filter,
          sticker_filter: r.sticker_filter,
          enabled: r.enabled,
          webhook_ids: r.webhook_ids,
          created_at: r.created_at,
          updated_at: r.updated_at,
        })),
        webhooks: webhooks.map(w => ({
          id: w.id,
          name: w.name,
          webhook_type: w.webhook_type,
          notification_style: w.notification_style,
          is_active: w.is_active,
          created_at: w.created_at,
          updated_at: w.updated_at,
          // webhook_url omitted for security (encrypted)
        })),
        alerts: alerts.map(a => ({
          id: a.id,
          rule_id: a.rule_id,
          item_name: a.item_name,
          price: a.price,
          wear_value: a.wear_value,
          stattrak: a.stattrak,
          souvenir: a.souvenir,
          has_stickers: a.has_stickers,
          skin_url: a.skin_url,
          sale_id: a.sale_id,
          notified_at: a.notified_at,
          sent_at: a.sent_at,
        })),
        audit_logs: auditLogs.map(l => ({
          id: l.id,
          event_type: l.event_type,
          event_data: l.event_data,
          ip_address: l.ip_address,
          user_agent: l.user_agent,
          created_at: l.created_at,
        })),
        passkeys: passkeys.map(p => ({
          id: p.id,
          name: p.name,
          device_type: p.device_type,
          backed_up: p.backed_up,
          last_used_at: p.last_used_at,
          created_at: p.created_at,
        })),
        sanctions: sanctionsHistory.map(s => ({
          id: s.id,
          action: s.action,
          restriction_type: s.restriction_type,
          reason: s.reason,
          duration_hours: s.duration_hours,
          expires_at: s.expires_at,
          admin_username: s.admin_username,
          created_at: s.created_at,
        })),
        exported_at: new Date().toISOString(),
      };

      // Log the export action
      await store.audit.createLog(userId, 'data_export', undefined, getClientIp(request), request.headers['user-agent']);

      return reply.status(200).send({
        success: true,
        data: exportData,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Data export');
    }
  });

  /**
   * GET /api/user/sessions - List active sessions
   */
  fastify.get('/sessions', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'List all active sessions for the current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  ip_address: { type: 'string', nullable: true },
                  user_agent: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                  expires_at: { type: 'string' },
                  is_current: { type: 'boolean' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const sessions = await store.auth.getActiveSessionsForUser(userId);

      // Identify current session by matching refresh token JTI
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      const data = sessions.map(s => ({
        id: s.id,
        ip_address: s.ip_address,
        user_agent: s.user_agent,
        created_at: s.created_at.toISOString(),
        expires_at: s.expires_at.toISOString(),
        is_current: s.token_jti === currentJti,
      }));

      return reply.status(200).send({ success: true, data });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List sessions');
    }
  });

  /**
   * DELETE /api/user/sessions/:id - Revoke a specific session
   */
  fastify.delete<{ Params: { id: string } }>('/sessions/:id', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Revoke a specific session by ID',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: { id: { type: 'string', pattern: '^[0-9]+$' } },
        required: ['id'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const sessionId = parseInt(request.params.id, 10);

      // Detect if the session being revoked is the current one
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      // Get session info before revoking to check if it's current
      const sessions = await store.auth.getActiveSessionsForUser(userId);
      const targetSession = sessions.find(s => s.id === sessionId);
      const isCurrentSession = targetSession && currentJti && targetSession.token_jti === currentJti;

      const { revoked, accessTokenJti } = await store.auth.revokeSessionById(sessionId, userId);
      if (!revoked) {
        throw new AppError(404, 'Session not found or already revoked', 'SESSION_NOT_FOUND');
      }

      // Blacklist the access token associated with the revoked session
      if (accessTokenJti) {
        // Access tokens expire in 10 min, use a safe upper bound
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await store.auth.blacklistAccessToken(accessTokenJti, userId, accessExpiry, 'session_revoked');
      }

      // If revoking the current session, also blacklist current access token and clear cookies
      let loggedOut = false;
      if (isCurrentSession) {
        const accessToken = AuthService.extractTokenFromHeader(request.headers.authorization ?? '') || request.cookies?.[ACCESS_COOKIE];
        if (accessToken) {
          const tokenPayload = AuthService.verifyToken(accessToken, 'access');
          if (tokenPayload?.jti) {
            const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
            await store.auth.blacklistAccessToken(tokenPayload.jti, userId, exp, 'session_revoked');
          }
        }
        clearAuthCookies(reply);
        loggedOut = true;
      }

      await store.audit.createLog(
        userId,
        'session_revoked',
        JSON.stringify({ method: 'user_self', session_id: sessionId, session_user_agent: targetSession?.user_agent ?? null }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: loggedOut ? 'Current session revoked. You have been logged out.' : 'Session revoked successfully.',
        logged_out: loggedOut,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Revoke session');
    }
  });

  /**
   * DELETE /api/user/sessions - Revoke all other sessions (keep current)
   */
  fastify.delete('/sessions', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Revoke all other sessions — keeps the current session active',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;

      // Get current session JTI to preserve it
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      if (currentJti) {
        const revokedAccessJtis = await store.auth.revokeAllOtherSessions(userId, currentJti);
        // Blacklist all access tokens from revoked sessions
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await Promise.all(
          revokedAccessJtis.map(jti =>
            store.auth.blacklistAccessToken(jti, userId, accessExpiry, 'other_sessions_revoked')
          )
        );
      } else {
        // Can't identify current session, revoke all + blacklist access tokens
        const revokedJtis = await store.auth.revokeAllForUser(userId);
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, userId, accessExpiry, 'all_sessions_revoked')));
      }

      await store.audit.createLog(
        userId,
        'other_sessions_revoked',
        JSON.stringify({ method: 'user_self' }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: 'All other sessions have been revoked.',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Revoke sessions');
    }
  });

  /**
   * DELETE /api/user/account - Delete current user account
   */
  fastify.delete('/account', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Delete current user account and all associated data',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          password: { type: 'string', maxLength: 128 },
          totp_code: { type: 'string', maxLength: 8, description: 'Required for OAuth-only users with 2FA enabled' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { password, totp_code } = validateWithZod(DeleteAccountSchema, request.body);

      const user = await store.users.findById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // SECURITY: Prevent admins from deleting themselves (could leave system without admins)
      if (user.is_admin) {
        const adminCount = await store.users.countAdmins();
        if (adminCount <= 1) {
          throw new AppError(403, 'Cannot delete your account: you are the last administrator. Transfer admin privileges first.', 'LAST_ADMIN');
        }
      }

      // Verify identity before allowing account deletion
      if (user.password_hash) {
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      } else if (user.totp_enabled) {
        // OAuth-only users with 2FA must provide TOTP code or recovery code
        if (!totp_code) {
          throw new AppError(400, '2FA code is required to delete your account', 'TOTP_REQUIRED');
        }
        const userWith2FA = await store.users.findById(userId, true);
        if (userWith2FA) {
          await verifyTotpOrRecoveryCode(userWith2FA, totp_code, request, 'account_delete');
        }
      }
      // OAuth-only users without 2FA can delete without extra verification (confirmed on frontend)

      // Log self-deletion in admin_actions (survives CASCADE delete on user)
      await store.audit.logAdminAction(
        userId,
        'account_self_deleted',
        userId,
        JSON.stringify({ username: user.username, email: user.email, was_admin: user.is_admin }),
      );

      // Clean up avatar file from disk before deleting user
      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      // Blacklist the current access token BEFORE deleting the user,
      // because access_token_blacklist.user_id has a FK to users.id.
      const accessToken = AuthService.extractTokenFromHeader(request.headers.authorization ?? '') || request.cookies?.[ACCESS_COOKIE];
      if (accessToken) {
        const tokenPayload = AuthService.verifyToken(accessToken, 'access');
        if (tokenPayload?.jti) {
          const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
          await store.auth.blacklistAccessToken(tokenPayload.jti, userId, exp, 'account_deleted');
        }
      }

      // Delete user (CASCADE will automatically delete all associated data including refresh tokens)
      await store.users.delete(userId);

      // Clear auth cookies so the browser doesn't retain stale tokens
      clearAuthCookies(reply);

      return reply.status(200).send({
        success: true,
        message: 'Account deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete account');
    }
  });
}
