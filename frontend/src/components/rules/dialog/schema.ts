import * as z from 'zod'

export const ruleFormSchema = z.object({
  search_item: z.string().min(1, 'Search item is required').max(200, 'Search item is too long'),
  min_price: z.number().min(0, 'Minimum price must be positive').optional(),
  max_price: z.number().min(0, 'Maximum price must be positive').optional(),
  min_wear: z.number().min(0, 'Min wear must be between 0 and 100').max(100, 'Min wear must be between 0 and 100').optional(),
  max_wear: z.number().min(0, 'Max wear must be between 0 and 100').max(100, 'Max wear must be between 0 and 100').optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']),
  souvenir_filter: z.enum(['all', 'only', 'exclude']),
  sticker_filter: z.enum(['all', 'only', 'exclude']),
  webhook_ids: z.array(z.number()).max(10, 'Maximum 10 webhooks allowed'),
  enabled: z.boolean().optional(),
}).refine(
  (data) => data.min_price == null || data.max_price == null || data.min_price <= data.max_price,
  { message: 'Minimum price must be ≤ maximum price', path: ['min_price'] }
).refine(
  (data) => data.min_wear == null || data.max_wear == null || data.min_wear <= data.max_wear,
  { message: 'Minimum wear must be ≤ maximum wear', path: ['min_wear'] }
)

export type RuleFormData = z.infer<typeof ruleFormSchema>

export const defaultRuleFormValues: RuleFormData = {
  search_item: '',
  min_price: undefined,
  max_price: undefined,
  min_wear: undefined,
  max_wear: undefined,
  stattrak_filter: 'all',
  souvenir_filter: 'all',
  sticker_filter: 'all',
  webhook_ids: [],
  enabled: true,
}
