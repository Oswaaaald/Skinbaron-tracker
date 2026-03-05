import { z } from 'zod';
import { RuleBaseSchema } from '../../database/validation-schemas.js';

const RuleRequestBaseSchema = RuleBaseSchema.omit({
  id: true,
  user_id: true,
  created_at: true,
  updated_at: true,
});

type RuleRangeInput = {
  min_price?: number | null;
  max_price?: number | null;
  min_wear?: number | null;
  max_wear?: number | null;
};

const hasValidPriceRange = (data: RuleRangeInput) =>
  data.min_price == null || data.max_price == null || data.min_price <= data.max_price;

const hasValidWearRange = (data: RuleRangeInput) =>
  data.min_wear == null || data.max_wear == null || data.min_wear <= data.max_wear;

export const CreateRuleRequestSchema = RuleRequestBaseSchema
  .refine(
    hasValidPriceRange,
    { message: 'Minimum price must be less than or equal to maximum price', path: ['min_price'] },
  )
  .refine(
    hasValidWearRange,
    { message: 'Minimum wear must be less than or equal to maximum wear', path: ['min_wear'] },
  );

export const UpdateRuleRequestSchema = RuleRequestBaseSchema.partial()
  .refine(
    hasValidPriceRange,
    { message: 'Minimum price must be less than or equal to maximum price', path: ['min_price'] },
  )
  .refine(
    hasValidWearRange,
    { message: 'Minimum wear must be less than or equal to maximum wear', path: ['min_wear'] },
  )
  .refine(
    data => Object.keys(data).length > 0,
    { message: 'At least one field must be provided' },
  );

export const RuleParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});
