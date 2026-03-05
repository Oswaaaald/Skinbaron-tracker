import crypto from 'crypto';
import type { FastifyInstance } from 'fastify';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { PasskeyAuthVerifySchema } from '../../database/schemas.js';
import type { AuthRoutesContext } from './shared.js';

const PASSKEY_CHALLENGE_TTL = 5 * 60 * 1000;

export function registerPasskeyAuthRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  const rpID = appConfig.WEBAUTHN_RP_ID;
  const rpOrigin = appConfig.WEBAUTHN_RP_ORIGIN;

  /**
   * POST /api/auth/passkey/authenticate-options - Generate authentication options (no auth required)
   */
  fastify.post('/passkey/authenticate-options', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Generate WebAuthn authentication options',
      tags: ['Authentication'],
    },
  }, async (_request, reply) => {
    try {
      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: 'preferred',
      });

      // Use a random key since the user is not yet identified
      const challengeKey = crypto.randomBytes(16).toString('hex');
      await store.challenges.store(`passkey_authn:${challengeKey}`, 'passkey_authn', options.challenge, PASSKEY_CHALLENGE_TTL);

      return reply.status(200).send({
        success: true,
        data: {
          ...options,
          challengeKey,
        },
      });
    } catch (error) {
      return handleRouteError(error, _request, reply, 'Passkey authenticate options');
    }
  });

  /**
   * POST /api/auth/passkey/authenticate-verify - Verify authentication response (no auth required)
   */
  fastify.post('/passkey/authenticate-verify', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Verify WebAuthn authentication',
      tags: ['Authentication'],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          credential: { type: 'object', maxProperties: 20 },
          challengeKey: { type: 'string' },
        },
        required: ['credential', 'challengeKey'],
      },
    },
  }, async (request, reply) => {
    try {
      const { credential, challengeKey } = validateWithZod(PasskeyAuthVerifySchema, request.body);

      const challengeValue = await store.challenges.consume(`passkey_authn:${challengeKey}`);
      if (!challengeValue) {
        throw new AppError(400, 'Authentication challenge expired. Please try again.', 'CHALLENGE_EXPIRED');
      }

      // Extract credential ID from the response to find the passkey
      const cred = credential as { id?: string; rawId?: string; response?: unknown };
      if (!cred.id) throw new AppError(400, 'Missing credential ID', 'INVALID_CREDENTIAL');

      const passkey = await store.passkeys.findByCredentialId(cred.id);
      if (!passkey) {
        // Don't reveal whether the credential exists — use generic message
        throw new AppError(401, 'Authentication failed', 'AUTH_FAILED');
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: credential as unknown as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
          expectedChallenge: challengeValue,
          expectedOrigin: rpOrigin,
          expectedRPID: rpID,
          credential: {
            id: passkey.credential_id,
            publicKey: new Uint8Array(Buffer.from(passkey.public_key, 'base64url')),
            counter: passkey.counter,
            transports: passkey.transports ? (JSON.parse(passkey.transports) as AuthenticatorTransportFuture[]) : undefined,
          },
          requireUserVerification: false,
        });
      } catch (verifyErr) {
        request.log.error({ err: verifyErr }, 'verifyAuthenticationResponse failed');
        throw new AppError(401, 'Authentication failed', 'VERIFICATION_FAILED');
      }

      if (!verification.verified) {
        throw new AppError(401, 'Authentication failed', 'VERIFICATION_FAILED');
      }

      // Update counter
      await store.passkeys.updateCounter(passkey.credential_id, verification.authenticationInfo.newCounter);

      // Look up the user
      const user = await store.users.findById(passkey.user_id);
      if (!user) throw new AppError(401, 'Authentication failed', 'AUTH_FAILED');
      if (!user.is_approved) throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');

      // Check moderation status (same logic as password login)
      const passkeyRestriction = await enforceRestriction(user);
      if (passkeyRestriction.result === 'blocked') {
        await store.audit.createLog(user.id, 'login_failed', JSON.stringify({ reason: 'account_restricted', method: 'passkey', restriction_type: user.restriction_type }), getClientIp(request), request.headers['user-agent']);
        throw new AppError(403, passkeyRestriction.errorMessage, 'ACCOUNT_RESTRICTED',
          passkeyRestriction.expiresAt ? { restriction_expires_at: passkeyRestriction.expiresAt } : undefined);
      }

      // Generate tokens and set cookies
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      await store.auth.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
      setAuthCookies(reply, accessToken, refreshToken);

      // Audit log
      await store.audit.createLog(
        user.id,
        'login_success',
        JSON.stringify({ method: 'passkey', passkey_id: passkey.id }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        data: {
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
          use_gravatar: user.use_gravatar,
          is_admin: user.is_admin,
          is_super_admin: user.is_super_admin,
          has_password: !!user.password_hash,
          token_expires_at: accessToken.expiresAt,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey authenticate verify');
    }
  });
}
