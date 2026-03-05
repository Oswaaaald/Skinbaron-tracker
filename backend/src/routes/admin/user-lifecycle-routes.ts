import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser, invalidateUserCache } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { deleteAvatarFile } from '../../lib/avatar.js';
import { AdminUserParamsSchema } from '../../database/validation-schemas.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminUserLifecycleRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
  fastify.delete('/users/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Delete a user and all their data (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
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
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);
      const adminId = getAuthUser(request).id;

      if (id === adminId) {
        throw Errors.forbidden('You cannot delete your own account');
      }

      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      if (!user.is_approved) {
        throw Errors.forbidden('Pending users must be approved or rejected before they can be managed');
      }

      const currentAdmin = await store.users.findById(adminId);
      if (!currentAdmin?.is_super_admin) {
        throw Errors.forbidden('Only super administrators can delete users');
      }

      if (user.is_super_admin) {
        throw Errors.forbidden('Cannot delete a super administrator account');
      }

      if (user.is_admin) {
        const adminCount = await store.users.countAdmins();
        if (adminCount <= 1) {
          throw Errors.badRequest('You cannot delete the last administrator account');
        }
      }

      await store.audit.logAdminAction(adminId, 'delete_user', id, `Deleted user ${user.username} (${user.email})`);

      const admin = await store.users.findById(adminId);
      await store.audit.createLog(
        adminId,
        'user_deleted',
        JSON.stringify({
          deleted_user_id: id,
          deleted_by_admin_id: adminId,
          admin_username: admin?.username,
          username: user.username,
          email: user.email,
        }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      const revokedJtis = await store.auth.revokeAllForUser(id);
      const accessExpiry = Date.now() + 15 * 60 * 1000;
      await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, id, accessExpiry, 'account_deleted')));

      invalidateUserCache(id);

      if (user.is_restricted && user.restriction_type === 'permanent') {
        await store.unbanEmail(user.email);

        const oauthAccounts = await store.oauth.findByUserId(id);
        for (const acc of oauthAccounts) {
          if (acc.provider_email && acc.provider_email !== user.email) {
            await store.unbanEmail(acc.provider_email);
          }
        }
      }

      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      const deleted = await store.users.delete(id);
      if (!deleted) {
        throw Errors.internal('Failed to delete user');
      }

      return reply.status(200).send({
        success: true,
        message: `User ${user.username} deleted successfully`,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete user');
    }
  });
}
