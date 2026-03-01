import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { z } from 'zod';
import crypto from 'crypto';
import zxcvbn from 'zxcvbn';

// Password strength validator using zxcvbn
const strongPasswordValidator = (password: string) => {
  const result = zxcvbn(password);
  // Score 0-4: 0=weak, 1=weak, 2=fair, 3=good, 4=strong
  // Require at least score 3 (good) to prevent common/weak passwords
  return result.score >= 3;
};

// User schemas
export const UserRegistrationSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be at most 128 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase and number')
    .refine(strongPasswordValidator, {
      message: 'Password is too weak. Avoid common words, keyboard patterns, or repeating characters.',
    }),
  tos_accepted: z.literal(true, { error: 'You must accept the Terms of Service' }),
});

export const UserLoginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required').max(128),
  totp_code: z.string().min(6).max(8).regex(/^[0-9A-Fa-f]+$/, '2FA code must contain only digits or recovery code characters').optional(),
});

export const PasswordChangeSchema = z.object({
  current_password: z.string().min(1, 'Current password is required').max(128),
  new_password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be at most 128 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase and number')
    .refine(strongPasswordValidator, {
      message: 'Password is too weak. Avoid common words, keyboard patterns, or repeating characters.',
    }),
});

/** Schema for OAuth users setting a password for the first time */
export const SetPasswordSchema = z.object({
  new_password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be at most 128 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase and number')
    .refine(strongPasswordValidator, {
      message: 'Password is too weak. Avoid common words, keyboard patterns, or repeating characters.',
    }),
  totp_code: z.string().max(8).optional(),
});

import { appConfig } from './config.js';

// Separate JWT secrets for access and refresh tokens (falls back to JWT_SECRET)
const JWT_ACCESS_SECRET = appConfig.JWT_ACCESS_SECRET;
const JWT_REFRESH_SECRET = appConfig.JWT_REFRESH_SECRET;
const ACCESS_TOKEN_TTL = '10m';
const REFRESH_TOKEN_TTL = '14d';

type TokenType = 'access' | 'refresh';

function getSecret(type: TokenType): string {
  return type === 'access' ? JWT_ACCESS_SECRET : JWT_REFRESH_SECRET;
}

export type TokenPayload = JwtPayload & {
  userId: number;
  jti: string;
  type: TokenType;
};

export class AuthService {
  
  /**
   * Hash a password
   */
  static async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  /**
   * Verify a password
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Generate short-lived access token with unique JTI
   */
  static generateAccessToken(userId: number): { token: string; jti: string; expiresAt: number } {
    const jti = crypto.randomUUID();
    const token = jwt.sign({ userId, jti, type: 'access' satisfies TokenType }, getSecret('access'), {
      expiresIn: ACCESS_TOKEN_TTL,
    });
    const payload = this.decodeToken(token);
    return {
      token,
      jti,
      expiresAt: payload?.exp ? payload.exp * 1000 : Date.now() + 15 * 60 * 1000,
    };
  }

  /**
   * Generate refresh token with rotation JTI
   */
  static generateRefreshToken(userId: number): { token: string; jti: string; expiresAt: number } {
    const jti = crypto.randomUUID();
    const token = jwt.sign({ userId, jti, type: 'refresh' satisfies TokenType }, getSecret('refresh'), {
      expiresIn: REFRESH_TOKEN_TTL,
    });
    const payload = this.decodeToken(token);
    return {
      token,
      jti,
      expiresAt: payload?.exp ? payload.exp * 1000 : Date.now() + 30 * 24 * 60 * 60 * 1000,
    };
  }

  /**
   * Verify JWT token — expectedType is required to prevent token type confusion
   */
  static verifyToken(token: string, expectedType: TokenType): TokenPayload | null {
    try {
      const payload = jwt.verify(token, getSecret(expectedType), { algorithms: ['HS256'] }) as TokenPayload;
      if (payload.type !== expectedType) return null;
      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Decode token without verification (used for expiry computation)
   */
  static decodeToken(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload | null;
    } catch {
      return null;
    }
  }

  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }

  /**
   * Generate Gravatar URL from email
   */
  static getGravatarUrl(email: string, size: number = 80): string {
    const hash = crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex');
    return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon`;
  }

  /**
   * Resolve the avatar URL for a user.
   * Priority: custom upload > gravatar (if enabled) > null
   */
  static getAvatarUrl(
    user: { email: string; avatar_filename?: string | null; use_gravatar?: boolean },
    apiBaseUrl: string,
  ): string | null {
    if (user.avatar_filename) {
      return `${apiBaseUrl}/api/avatars/${user.avatar_filename}`;
    }
    if (user.use_gravatar !== false) {
      return AuthService.getGravatarUrl(user.email);
    }
    return null;
  }
}