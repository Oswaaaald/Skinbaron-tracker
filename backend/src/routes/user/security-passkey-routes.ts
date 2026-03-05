import type { FastifyInstance } from 'fastify';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { resolvePasskeyName } from '../../lib/passkey-aaguids.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  PasskeyParamsSchema,
  PasskeyRenameSchema,
  PasskeyRegisterVerifySchema,
} from '../../database/schemas.js';
import { WEBAUTHN_CHALLENGE_TTL, type RegisterUserSecurityRoutesOptions } from './security-types.js';

export function registerUserPasskeyRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserSecurityRoutesOptions,
): void {
  const rpID = appConfig.WEBAUTHN_RP_ID;
  const rpName = appConfig.WEBAUTHN_RP_NAME;
  const rpOrigin = appConfig.WEBAUTHN_RP_ORIGIN;

  fastify.get('/passkeys', {
    schema: {
      description: 'List registered passkeys',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const keys = await store.passkeys.findByUserId(userId);
      return reply.status(200).send({
        success: true,
        data: keys.map((k) => ({
          id: k.id,
          name: k.name,
          device_type: k.device_type,
          backed_up: k.backed_up,
          transports: k.transports ? JSON.parse(k.transports) as string[] : [],
          created_at: k.created_at,
          last_used_at: k.last_used_at,
        })),
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List passkeys');
    }
  });

  fastify.post('/passkeys/register-options', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Generate WebAuthn registration options',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      const existingKeys = await store.passkeys.findByUserId(userId);
      if (existingKeys.length >= 10) {
        throw new AppError(400, 'Maximum of 10 passkeys allowed per account', 'MAX_PASSKEYS_REACHED');
      }

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userName: user.username,
        userDisplayName: user.username,
        attestationType: 'none',
        excludeCredentials: existingKeys.map((k) => ({
          id: k.credential_id,
          transports: k.transports ? (JSON.parse(k.transports) as AuthenticatorTransportFuture[]) : undefined,
        })),
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'preferred',
        },
      });

      await store.challenges.store(
        `webauthn_reg:${userId}`,
        'webauthn_registration',
        options.challenge,
        WEBAUTHN_CHALLENGE_TTL,
      );

      return reply.status(200).send({ success: true, data: options });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey register options');
    }
  });

  fastify.post('/passkeys/register-verify', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Verify WebAuthn registration response',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          credential: { type: 'object', maxProperties: 20 },
          name: { type: 'string', maxLength: 64 },
        },
        required: ['credential'],
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { credential, name: rawName } = validateWithZod(PasskeyRegisterVerifySchema, request.body);

      const name = rawName ? rawName.trim().replace(/[<>]/g, '').slice(0, 64) : undefined;
      const challengeValue = await store.challenges.consume(`webauthn_reg:${userId}`);
      if (!challengeValue) {
        throw new AppError(400, 'Registration challenge expired. Please try again.', 'CHALLENGE_EXPIRED');
      }

      const verification = await verifyRegistrationResponse({
        response: credential as unknown as Parameters<typeof verifyRegistrationResponse>[0]['response'],
        expectedChallenge: challengeValue,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new AppError(400, 'Passkey verification failed', 'VERIFICATION_FAILED');
      }

      const { credential: cred, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;
      const credentialIdB64 = cred.id;
      const publicKeyB64 = Buffer.from(cred.publicKey).toString('base64url');
      const detectedName = resolvePasskeyName(aaguid, credentialDeviceType, cred.transports);

      const passkey = await store.passkeys.create({
        user_id: userId,
        credential_id: credentialIdB64,
        public_key: publicKeyB64,
        counter: cred.counter,
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp,
        transports: cred.transports ? JSON.stringify(cred.transports) : undefined,
        name: name || detectedName,
      });

      await store.audit.createLog(
        userId,
        'passkey_registered',
        JSON.stringify({ passkey_id: passkey.id, name: passkey.name, device_type: credentialDeviceType, aaguid }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        data: {
          id: passkey.id,
          name: passkey.name,
          device_type: passkey.device_type,
          backed_up: passkey.backed_up,
          created_at: passkey.created_at,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey register verify');
    }
  });

  fastify.patch<{ Params: { id: string } }>('/passkeys/:id', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Rename a passkey',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: { name: { type: 'string', minLength: 1, maxLength: 64 } },
        required: ['name'],
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id: passkeyId } = validateWithZod(PasskeyParamsSchema, request.params);
      const { name } = validateWithZod(PasskeyRenameSchema, request.body);

      const updated = await store.passkeys.rename(passkeyId, userId, name);
      if (!updated) throw new AppError(404, 'Passkey not found', 'NOT_FOUND');

      return reply.status(200).send({ success: true, message: 'Passkey renamed', data: { id: updated.id, name: updated.name } });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Rename passkey');
    }
  });

  fastify.delete<{ Params: { id: string } }>('/passkeys/:id', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Delete a passkey',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id: passkeyId } = validateWithZod(PasskeyParamsSchema, request.params);

      const deleted = await store.passkeys.delete(passkeyId, userId);
      if (!deleted) throw new AppError(404, 'Passkey not found', 'NOT_FOUND');

      await store.audit.createLog(
        userId,
        'passkey_deleted',
        JSON.stringify({ passkey_id: passkeyId }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({ success: true, message: 'Passkey deleted' });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete passkey');
    }
  });
}
