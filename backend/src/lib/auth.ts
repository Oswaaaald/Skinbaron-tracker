import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { z } from 'zod';
import crypto from 'crypto';

// User schemas
export const UserRegistrationSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores'),
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase and number'),
});

export const UserLoginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
});

export const PasswordChangeSchema = z.object({
  current_password: z.string().min(1, 'Current password is required'),
  new_password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase and number'),
});

export const WebhookSchema = z.object({
  id: z.number().optional(),
  user_id: z.number(),
  name: z.string().min(1, 'Webhook name is required').max(50, 'Webhook name must be at most 50 characters'),
  webhook_url: z.string().url('Please enter a valid webhook URL'),
  created_at: z.string().optional(),
});

// Types
export type UserWebhook = z.infer<typeof WebhookSchema>;
export type CreateWebhook = Omit<UserWebhook, 'id' | 'created_at'>;

import { appConfig } from './config.js';

// JWT secret from config
const JWT_SECRET = appConfig.JWT_SECRET;
const ACCESS_TOKEN_TTL = '10m';
const REFRESH_TOKEN_TTL = '14d';

type TokenType = 'access' | 'refresh';

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
    const token = jwt.sign({ userId, jti, type: 'access' satisfies TokenType }, JWT_SECRET, {
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
    const token = jwt.sign({ userId, jti, type: 'refresh' satisfies TokenType }, JWT_SECRET, {
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
   * Verify JWT token
   */
  static verifyToken(token: string, expectedType?: TokenType): TokenPayload | null {
    try {
      const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
      if (expectedType && payload.type !== expectedType) return null;
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
}