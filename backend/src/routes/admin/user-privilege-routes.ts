import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser, invalidateUserCache } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import {
  AdminUserParamsSchema,
  AdminToggleSchema,
  AdminUsernameSchema,
  AdminResetSchema,
} from '../../database/schemas.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminUserPrivilegeRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
  fastify.patch('/users/:id/admin', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Toggle admin status for a user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['is_admin'],
        properties: {
          is_admin: { type: 'boolean' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                username: { type: 'string' },
                is_admin: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const { is_admin } = validateWithZod(AdminToggleSchema, request.body);
      const adminId = getAuthUser(request).id;

      if (id === adminId) {
        throw Errors.forbidden('You cannot change your own administrator privileges');
      }

      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      if (!user.is_approved) {
        throw Errors.forbidden('Cannot change admin status for a pending user');
      }

      const currentAdmin = await store.users.findById(adminId);
      if (!currentAdmin?.is_super_admin) {
        throw Errors.forbidden('Only super administrators can manage admin privileges');
      }

      if (user.is_super_admin) {
        throw Errors.forbidden('Cannot modify administrator privileges of a super administrator');
      }

      if (user.is_admin && !is_admin) {
        const adminCount = await store.users.countAdmins();
        if (adminCount <= 1) {
          throw Errors.badRequest('You cannot remove administrator privileges from the last admin');
        }
      }

      const updated = await store.users.toggleAdmin(id, is_admin);
      if (!updated) {
        throw Errors.internal('Failed to update admin status');
      }

      invalidateUserCache(id);

      const action = is_admin ? 'grant_admin' : 'revoke_admin';
      const details = `${is_admin ? 'Granted' : 'Revoked'} admin privileges for ${user.username}`;
      await store.audit.logAdminAction(adminId, action, id, details);

      const eventType = is_admin ? 'user_promoted' : 'user_demoted';
      await store.audit.createLog(
        id,
        eventType,
        JSON.stringify({ admin_id: adminId, is_admin }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: `Admin status updated for ${user.username}`,
        data: { is_admin },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Toggle admin status');
    }
  });

  fastify.patch('/users/:id/username', {
    config: { rateLimit: adminWriteRateLimit },
    schema: {
      description: 'Change a user username (admin moderation)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'integer', minimum: 1 } } },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['username'],
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 20, pattern: '^[a-zA-Z0-9_]+$' },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const { username } = validateWithZod(AdminUsernameSchema, request.body);
      const adminId = getAuthUser(request).id;

      const user = await store.users.findById(id);
      if (!user) throw Errors.notFound('User');

      if (user.is_admin || user.is_super_admin) {
        const currentAdmin = await store.users.findById(adminId);
        if (!currentAdmin?.is_super_admin) throw Errors.forbidden('Only super admins can change admin usernames');
      }

      if (user.username === username) {
        throw Errors.badRequest('New username is the same as the current one');
      }

      const existing = await store.users.findByUsername(username);
      if (existing) {
        throw Errors.conflict('This username is already taken');
      }

      const admin = await store.users.findById(adminId);
      const adminUsername = admin?.username || 'Unknown';
      const oldUsername = user.username;

      await store.users.update(id, { username });
      invalidateUserCache(id);

      await store.audit.logAdminAction(adminId, 'change_username', id, `Changed username from "${oldUsername}" to "${username}"`);
      await store.audit.createLog(
        id,
        'username_changed',
        JSON.stringify({ old_username: oldUsername, new_username: username, changed_by_admin: adminId, admin_username: adminUsername }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: `Username changed from "${oldUsername}" to "${username}"`,
        data: { username },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Change username');
    }
  });

  fastify.post('/users/:id/reset', {
    config: { rateLimit: adminWriteRateLimit },
    schema: {
      description: 'Reset specific user data (2FA, passkeys, or sessions)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'integer', minimum: 1 } } },
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['target'],
        properties: {
          target: { type: 'string', enum: ['2fa', 'passkeys', 'sessions'] },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const { target } = validateWithZod(AdminResetSchema, request.body);
      const adminId = getAuthUser(request).id;

      const user = await store.users.findById(id);
      if (!user) throw Errors.notFound('User');

      if (user.is_super_admin) {
        throw Errors.forbidden('Cannot reset data for super administrators');
      }

      if (user.is_admin) {
        const currentAdmin = await store.users.findById(adminId);
        if (!currentAdmin?.is_super_admin) throw Errors.forbidden('Only super admins can reset admin data');
      }

      const admin = await store.users.findById(adminId);
      const adminUsername = admin?.username || 'Unknown';
      let description: string;

      switch (target) {
        case '2fa': {
          if (!user.totp_enabled) {
            throw Errors.badRequest('User does not have 2FA enabled');
          }
          await store.users.update(id, {
            totp_enabled: false,
            totp_secret_encrypted: null,
            recovery_codes_encrypted: null,
          });
          description = `Reset 2FA (TOTP + recovery codes) for ${user.username}`;
          break;
        }
        case 'passkeys': {
          const count = await store.passkeys.countByUserId(id);
          if (count === 0) {
            throw Errors.badRequest('User has no passkeys');
          }
          const deleted = await store.passkeys.deleteAllByUserId(id);
          description = `Removed all passkeys (${deleted}) for ${user.username}`;
          break;
        }
        case 'sessions': {
          const revokedJtis = await store.auth.revokeAllForUser(id);
          const accessExpiry = Date.now() + 15 * 60 * 1000;
          await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, id, accessExpiry, 'sessions_reset_by_admin')));
          description = `Revoked all sessions for ${user.username}`;
          break;
        }
      }

      invalidateUserCache(id);

      await store.audit.logAdminAction(adminId, `reset_${target}`, id, description);
      await store.audit.createLog(
        id,
        `${target}_reset_by_admin`,
        JSON.stringify({ admin_id: adminId, admin_username: adminUsername, target }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: description,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Admin reset user data');
    }
  });
}
