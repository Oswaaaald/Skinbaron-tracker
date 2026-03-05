import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser, invalidateUserCache } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { SanctionParamsSchema } from '../../database/schemas.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminSanctionRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
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

      const admin = await store.users.findById(adminId);
      if (!admin?.is_super_admin) throw Errors.forbidden('Only super admins can delete sanctions');

      const sanction = await store.getSanctionById(sanctionId);
      if (!sanction) throw Errors.notFound('Sanction');

      const user = await store.users.findById(sanction.user_id);
      if (!user) throw Errors.notFound('User');

      if (sanction.action === 'restrict' && user.is_restricted) {
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
