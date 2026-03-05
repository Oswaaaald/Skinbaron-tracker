import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { AuthService } from '../../lib/auth.js';
import { appConfig } from '../../lib/config.js';
import {
  AdminUserParamsSchema,
  AdminUsersQuerySchema,
} from '../../database/validation-schemas.js';

export function registerAdminUserOverviewRoutes(fastify: FastifyInstance): void {
  fastify.get('/users', {
    schema: {
      description: 'List all users with pagination (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', default: 20, minimum: 1, maximum: 100 },
          offset: { type: 'integer', default: 0, minimum: 0 },
          sort_by: { type: 'string', enum: ['username', 'email', 'role', 'created_at', 'rules', 'alerts', 'webhooks'], default: 'created_at' },
          sort_dir: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          search: { type: 'string', maxLength: 200 },
          role: { type: 'string', enum: ['admin', 'user', 'all'], default: 'all' },
          status: { type: 'string', enum: ['all', 'sanctioned', 'active'], default: 'all' },
        },
      },
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
                  username: { type: 'string' },
                  email: { type: 'string' },
                  is_admin: { type: 'boolean' },
                  is_super_admin: { type: 'boolean' },
                  is_restricted: { type: 'boolean' },
                  restriction_type: { type: ['string', 'null'] },
                  restriction_expires_at: { type: ['string', 'null'] },
                  created_at: { type: 'string' },
                  avatar_url: { type: ['string', 'null'] },
                  stats: {
                    type: 'object',
                    properties: {
                      rules_count: { type: 'number' },
                      alerts_count: { type: 'number' },
                      webhooks_count: { type: 'number' },
                    },
                  },
                },
              },
            },
            pagination: {
              type: 'object',
              properties: {
                limit: { type: 'number' },
                offset: { type: 'number' },
                total: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const query = validateWithZod(AdminUsersQuerySchema, request.query);

      const limit = query.limit;
      const offset = query.offset;

      const { data: usersWithStats, total } = await store.users.findAllWithStatsPaginated({
        limit,
        offset,
        sortBy: query.sort_by,
        sortDir: query.sort_dir,
        search: query.search,
        role: query.role,
        status: query.status,
      });

      const result = usersWithStats.map(user => ({
        id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin || false,
        is_super_admin: user.is_super_admin || false,
        is_restricted: user.is_restricted || false,
        restriction_type: user.restriction_type || null,
        restriction_expires_at: user.restriction_expires_at,
        created_at: user.created_at,
        avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
        stats: user.stats,
      }));

      return reply.status(200).send({
        success: true,
        data: result,
        pagination: { limit, offset, total },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List users');
    }
  });

  fastify.get('/users/:id', {
    schema: {
      description: 'View detailed user profile (admin only, GDPR-audited)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);

      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      const [oauthAccounts, passkeysData, rules, webhooks, userStats, sanctionsData] = await Promise.all([
        store.oauth.findByUserId(id),
        store.passkeys.findByUserId(id),
        store.rules.findByUserId(id),
        store.webhooks.findByUserId(id, false),
        store.audit.getUserStats(id),
        store.getSanctionsByUserId(id),
      ]);

      return reply.status(200).send({
        success: true,
        data: {
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
          has_custom_avatar: !!user.avatar_filename,
          is_admin: user.is_admin || false,
          is_super_admin: user.is_super_admin || false,
          is_approved: user.is_approved || false,
          is_restricted: user.is_restricted || false,
          restriction_type: user.restriction_type || null,
          restriction_reason: user.restriction_reason || null,
          restriction_expires_at: user.restriction_expires_at,
          restricted_at: user.restricted_at,
          totp_enabled: user.totp_enabled || false,
          tos_accepted_at: user.tos_accepted_at,
          created_at: user.created_at,
          updated_at: user.updated_at,
          oauth_accounts: oauthAccounts.map(a => ({
            id: a.id,
            provider: a.provider,
            provider_email: a.provider_email,
            created_at: a.created_at,
          })),
          passkeys: passkeysData.map(p => ({
            id: p.id,
            name: p.name,
            device_type: p.device_type,
            backed_up: p.backed_up,
            created_at: p.created_at,
            last_used_at: p.last_used_at,
          })),
          stats: {
            rules_count: rules.length,
            active_rules_count: rules.filter(r => r.enabled).length,
            webhooks_count: webhooks.length,
            active_webhooks_count: webhooks.filter(w => w.is_active).length,
            alerts_count: userStats.totalAlerts,
          },
          sanctions: sanctionsData.map(s => ({
            id: s.id,
            admin_username: s.admin_username,
            action: s.action,
            restriction_type: s.restriction_type,
            reason: s.reason,
            duration_hours: s.duration_hours,
            expires_at: s.expires_at,
            created_at: s.created_at,
          })),
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'View user detail');
    }
  });
}
