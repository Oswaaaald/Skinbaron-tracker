import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';

type RegisterUserAccountExportRoutesOptions = {
  heavyOperationRateLimit: {
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

export function registerUserAccountExportRoutes(
  fastify: FastifyInstance,
  { heavyOperationRateLimit }: RegisterUserAccountExportRoutesOptions,
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
}
