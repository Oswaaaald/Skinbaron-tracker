import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { processAndSaveAvatar, deleteAvatarFile } from '../../lib/avatar.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { appConfig } from '../../lib/config.js';

const AvatarSettingsSchema = z.object({
  use_gravatar: z.boolean(),
});

type RegisterUserAvatarRoutesOptions = {
  avatarRateLimit: {
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

export function registerUserAvatarRoutes(
  fastify: FastifyInstance,
  { avatarRateLimit }: RegisterUserAvatarRoutesOptions,
): void {
  // ==================== Avatar Management ====================

  /**
   * POST /api/user/avatar - Upload a custom avatar image
   * Security: magic-byte validation, sharp re-encoding (strips EXIF/metadata),
   * random filename, size limit, rate limited
   */
  fastify.post('/avatar', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Upload a custom avatar image (max 5 MB, PNG/JPEG/WebP/GIF)',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      consumes: ['multipart/form-data'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                avatar_url: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      const file = await request.file();
      if (!file) {
        throw new AppError(400, 'No file uploaded', 'NO_FILE');
      }

      // Process image (validates magic bytes, resizes, strips metadata, converts to WebP)
      let filename: string;
      try {
        filename = await processAndSaveAvatar(file);
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to process image';
        throw new AppError(400, msg, 'INVALID_IMAGE');
      }

      // Delete old avatar file if it exists
      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      // Update database
      await store.users.update(userId, { avatar_filename: filename });

      // Audit log
      await store.audit.createLog(userId, 'avatar_uploaded', JSON.stringify({ filename }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, avatar_filename: filename }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar upload');
    }
  });

  /**
   * DELETE /api/user/avatar - Remove custom avatar (revert to gravatar or initials)
   */
  fastify.delete('/avatar', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Remove custom avatar',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                avatar_url: { type: 'string', nullable: true },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      await store.users.update(userId, { avatar_filename: null });

      await store.audit.createLog(userId, 'avatar_removed', JSON.stringify({ had_custom: !!user.avatar_filename }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, avatar_filename: null }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar delete');
    }
  });

  /**
   * PATCH /api/user/avatar-settings - Toggle Gravatar fallback
   */
  fastify.patch('/avatar-settings', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Toggle Gravatar fallback for avatar',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['use_gravatar'],
        properties: {
          use_gravatar: { type: 'boolean' },
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
                use_gravatar: { type: 'boolean' },
                avatar_url: { type: 'string', nullable: true },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { use_gravatar } = validateWithZod(AvatarSettingsSchema, request.body);

      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      await store.users.update(userId, { use_gravatar });

      await store.audit.createLog(userId, 'gravatar_toggled', JSON.stringify({ use_gravatar }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, use_gravatar }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { use_gravatar, avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar settings');
    }
  });
}
