import { request } from 'undici';
import { z } from 'zod';
import { appConfig, SKINBARON_API } from './config.js';

// SkinBaron API Response Schemas
export const SkinBaronItemSchema = z.object({
  saleId: z.string(),
  itemName: z.string(),
  price: z.number(),
  wearValue: z.number().optional(),
  statTrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  sellerName: z.string().optional(),
  currency: z.string().optional(),
  // Additional fields that might be returned
  quality: z.string().optional(),
  rarity: z.string().optional(),
  weapon: z.string().optional(),
  category: z.string().optional(),
});

export const SearchResponseSchema = z.object({
  success: z.boolean(),
  items: z.array(SkinBaronItemSchema).optional(),
  totalItems: z.number().optional(),
  message: z.string().optional(),
});

export const BestDealsResponseSchema = z.object({
  success: z.boolean(),
  items: z.array(SkinBaronItemSchema).optional(),
  message: z.string().optional(),
});

export const NewestItemsResponseSchema = z.object({
  success: z.boolean(),
  items: z.array(SkinBaronItemSchema).optional(),
  message: z.string().optional(),
});

// Types
export type SkinBaronItem = z.infer<typeof SkinBaronItemSchema>;
export type SearchResponse = z.infer<typeof SearchResponseSchema>;
export type BestDealsResponse = z.infer<typeof BestDealsResponseSchema>;
export type NewestItemsResponse = z.infer<typeof NewestItemsResponseSchema>;

// Search parameters
export interface SearchParams {
  search_item: string;
  min?: number;
  max?: number;
  minWear?: number;
  maxWear?: number;
  statTrak?: boolean;
  souvenir?: boolean;
  limit?: number;
}

export interface FeedParams {
  limit?: number;
  maxPrice?: number;
  maxWear?: number;
}

export class SkinBaronClient {
  private baseURL = SKINBARON_API.BASE_URL;
  private apiKey = appConfig.SB_API_KEY || undefined;
  private appId = SKINBARON_API.APP_ID;

  constructor() {
    // API key is optional - SkinBaron API is public for search
    console.log('🔍 SkinBaron client initialized', { hasApiKey: !!this.apiKey });
  }

  private async makeRequest<T>(
    endpoint: string, 
    params: Record<string, any> = {}, 
    schema: z.ZodSchema<T>
  ): Promise<T> {
    try {
      const baseParams: Record<string, string> = {
        appid: this.appId.toString(),
        ...this.sanitizeParams(params),
      };

      // Only add API key if provided
      if (this.apiKey) {
        baseParams.apikey = this.apiKey;
      }

      const searchParams = new URLSearchParams(baseParams);

      const url = `${this.baseURL}${endpoint}`;
      
      console.log(`🔍 SkinBaron API Request: ${endpoint}`, {
        params: Object.fromEntries(searchParams.entries()),
      });

      const { statusCode, body } = await request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'SkinBaron-Alerts/1.0',
        },
        body: searchParams.toString(),
      });

      if (statusCode !== 200) {
        throw new Error(`SkinBaron API error: ${statusCode}`);
      }

      const rawData = await body.text();
      let jsonData;
      
      try {
        jsonData = JSON.parse(rawData);
      } catch (parseError) {
        console.error('Failed to parse SkinBaron response:', rawData);
        throw new Error('Invalid JSON response from SkinBaron API');
      }

      // Validate response with schema
      const validatedData = schema.parse(jsonData);
      
      console.log(`✅ SkinBaron API Response: ${endpoint}`, {
        success: jsonData.success,
        itemCount: jsonData.items?.length || 0,
      });

      return validatedData;
    } catch (error) {
      console.error(`❌ SkinBaron API Error (${endpoint}):`, error);
      throw error;
    }
  }

  private sanitizeParams(params: Record<string, any>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        if (typeof value === 'boolean') {
          sanitized[key] = value ? '1' : '0';
        } else {
          sanitized[key] = String(value);
        }
      }
    }
    
    return sanitized;
  }

  /**
   * Search for items on SkinBaron
   */
  async search(params: SearchParams): Promise<SearchResponse> {
    const searchData = {
      search_item: params.search_item,
      ...(params.min !== undefined && { min: params.min }),
      ...(params.max !== undefined && { max: params.max }),
      ...(params.minWear !== undefined && { minWear: params.minWear }),
      ...(params.maxWear !== undefined && { maxWear: params.maxWear }),
      ...(params.statTrak !== undefined && { statTrak: params.statTrak }),
      ...(params.souvenir !== undefined && { souvenir: params.souvenir }),
      ...(params.limit !== undefined && { limit: params.limit }),
    };

    const result = await this.makeRequest(
      SKINBARON_API.ENDPOINTS.SEARCH,
      searchData,
      SearchResponseSchema
    );

    // Normalize items
    if (result.items) {
      result.items = result.items.map(item => this.normalizeItem(item));
    }

    return result;
  }

  /**
   * Get best deals from SkinBaron
   */
  async getBestDeals(params: FeedParams = {}): Promise<BestDealsResponse> {
    const feedData = {
      ...(params.limit !== undefined && { limit: params.limit }),
      ...(params.maxPrice !== undefined && { maxPrice: params.maxPrice }),
      ...(params.maxWear !== undefined && { maxWear: params.maxWear }),
    };

    const result = await this.makeRequest(
      SKINBARON_API.ENDPOINTS.BEST_DEALS,
      feedData,
      BestDealsResponseSchema
    );

    // Normalize items
    if (result.items) {
      result.items = result.items.map(item => this.normalizeItem(item));
    }

    return result;
  }

  /**
   * Get newest items from SkinBaron
   */
  async getNewestItems(params: FeedParams = {}): Promise<NewestItemsResponse> {
    const feedData = {
      ...(params.limit !== undefined && { limit: params.limit }),
      ...(params.maxPrice !== undefined && { maxPrice: params.maxPrice }),
      ...(params.maxWear !== undefined && { maxWear: params.maxWear }),
    };

    const result = await this.makeRequest(
      SKINBARON_API.ENDPOINTS.NEWEST_ITEMS,
      feedData,
      NewestItemsResponseSchema
    );

    // Normalize items
    if (result.items) {
      result.items = result.items.map(item => this.normalizeItem(item));
    }

    return result;
  }

  /**
   * Test API connection
   */
  async testConnection(): Promise<boolean> {
    // Temporarily skip the API test due to 415 errors
    // The API might need different authentication or the endpoint may have changed
    console.log('⚠️  SkinBaron API test skipped - endpoint needs verification');
    return false; // Mark as unhealthy but don't crash the application
  }

  /**
   * Generate SkinBaron listing URL
   */
  getSkinUrl(saleId: string): string {
    return `https://skinbaron.de/listing/${saleId}`;
  }



  /**
   * Check if an item matches the given filters
   */
  matchesFilters(item: SkinBaronItem, params: SearchParams): boolean {
    // Price filters
    if (params.min !== undefined && item.price < params.min) {
      return false;
    }
    if (params.max !== undefined && item.price > params.max) {
      return false;
    }

    // Wear filters
    if (item.wearValue !== undefined) {
      if (params.minWear !== undefined && item.wearValue < params.minWear) {
        return false;
      }
      if (params.maxWear !== undefined && item.wearValue > params.maxWear) {
        return false;
      }
    }

    // StatTrak filter
    if (params.statTrak !== undefined && item.statTrak !== params.statTrak) {
      return false;
    }

    // Souvenir filter
    if (params.souvenir !== undefined && item.souvenir !== params.souvenir) {
      return false;
    }

    // Item name filter (case-insensitive partial match)
    const itemName = item.itemName.toLowerCase();
    const searchItem = params.search_item.toLowerCase();
    if (!itemName.includes(searchItem)) {
      return false;
    }

    return true;
  }

  /**
   * Normalize item data (ensure defaults)
   */
  private normalizeItem(item: SkinBaronItem): SkinBaronItem {
    return {
      ...item,
      statTrak: item.statTrak ?? false,
      souvenir: item.souvenir ?? false,
      currency: item.currency ?? 'EUR',
    };
  }

  /**
   * Format item for display
   */
  formatItem(item: SkinBaronItem): string {
    const parts = [item.itemName];
    
    if (item.statTrak) parts.push('StatTrak™');
    if (item.souvenir) parts.push('Souvenir');
    if (item.wearValue) parts.push(`Wear: ${item.wearValue.toFixed(6)}`);
    
    parts.push(`${item.price} ${item.currency}`);
    
    return parts.join(' | ');
  }
}

// Singleton instance
let clientInstance: SkinBaronClient | null = null;

export const getSkinBaronClient = (): SkinBaronClient => {
  if (!clientInstance) {
    clientInstance = new SkinBaronClient();
  }
  return clientInstance;
};

export default getSkinBaronClient;