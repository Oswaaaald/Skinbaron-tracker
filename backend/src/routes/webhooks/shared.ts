import { z } from 'zod';

export const WebhookParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

export const WebhookQuerySchema = z.object({
  decrypt: z.string().default('false').transform(val => val === 'true'),
});
