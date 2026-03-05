import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { AuthService } from '../../lib/auth.js';
import { appConfig } from '../../lib/config.js';
import { deleteAvatarFile } from '../../lib/avatar.js';
import { AdminUserParamsSchema } from '../../database/schemas.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminUserAvatarRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
  fastify.delete('/users/:id/avatar', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Remove a user\'s custom avatar (admin only, GDPR-audited)',
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
      const adminId = getAuthUser(request).id;
      const admin = await store.users.findById(adminId);

      const user = await store.users.findById(id);
      if (!user) throw Errors.notFound('User');

      if (user.is_admin || user.is_super_admin) {
        if (!admin?.is_super_admin) throw Errors.forbidden('Only super admins can modify admin accounts');
      }

      if (!user.avatar_filename) {
        return reply.status(200).send({
          success: true,
          message: 'User has no custom avatar',
        });
      }

      await deleteAvatarFile(user.avatar_filename);
      await store.users.update(id, { avatar_filename: null });

      await store.audit.logAdminAction(adminId, 'admin_avatar_removed', id, `Removed custom avatar for ${user.username} (${user.email})`);
      await store.audit.createLog(
        id,
        'avatar_removed',
        JSON.stringify({ removed_by_admin: adminId, admin_username: admin?.username }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: 'User avatar removed successfully',
        data: {
          avatar_url: AuthService.getAvatarUrl({ ...user, avatar_filename: null }, appConfig.NEXT_PUBLIC_API_URL),
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Admin remove user avatar');
    }
  });
}
