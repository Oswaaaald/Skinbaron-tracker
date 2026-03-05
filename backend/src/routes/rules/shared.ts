import { z } from 'zod';
import { RuleBaseSchema } from '../../database/validation-schemas.js';

export const CreateRuleRequestSchema = RuleBaseSchema.omit({
  id: true,
  user_id: true,
  created_at: true,
  updated_at: true,
}).refine(
  data => data.min_price == null || data.max_price == null || data.min_price <= data.max_price,
  { message: 'Minimum price must be less than or equal to maximum price', path: ['min_price'] },
).refine(
  data => data.min_wear == null || data.max_wear == null || data.min_wear <= data.max_wear,
  { message: 'Minimum wear must be less than or equal to maximum wear', path: ['min_wear'] },
);

export const UpdateRuleRequestSchema = RuleBaseSchema.omit({
  id: true,
  user_id: true,
  created_at: true,
  updated_at: true,
}).partial();

export const RuleParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});
