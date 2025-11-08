import { request } from 'undici';
import { z } from 'zod';
import { appConfig, SKINBARON_API } from './config.js';

// SkinBaron API Response Schemas (matching official API)
export const SkinBaronSaleSchema = z.object({
  id: z.string(), // SkinBaron sale ID
  price: z.number(),
  img: z.string().optional(), // Steam image URL
  market_name: z.string(), // Steam market hash name
  // Additional fields that might be returned
  wear: z.number().optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  seller: z.string().optional(),
  currency: z.string().optional(),
  quality: z.string().optional(),
  rarity: z.string().optional(),
});

export const SearchResponseSchema = z.object({
  sales: z.array(SkinBaronSaleSchema).optional(),
});

// Types for the actual API response structure
export type SkinBaronSale = z.infer<typeof SkinBaronSaleSchema>;
export type SearchResponse = z.infer<typeof SearchResponseSchema>;

// Legacy type for backward compatibility - we'll adapt sales to items
export interface SkinBaronItem {
  saleId: string;
  itemName: string;
  price: number;
  wearValue?: number;
  statTrak?: boolean;
  souvenir?: boolean;
  sellerName?: string;
  currency?: string;
  quality?: string;
  rarity?: string;
}

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



export class SkinBaronClient {
  private baseURL = SKINBARON_API.BASE_URL;
  private apiKey = appConfig.SB_API_KEY || undefined;
  private appId = SKINBARON_API.APP_ID;

  constructor() {
    // API key is optional - SkinBaron API is public for search
  }

  private async makeRequest<T>(
    endpoint: string, 
    params: Record<string, any> = {}, 
    schema: z.ZodSchema<T>
  ): Promise<T> {
    try {
      const requestBody: Record<string, any> = {
        appid: this.appId,
        ...params,
      };

      // Only add API key if provided
      if (this.apiKey) {
        requestBody.apikey = this.apiKey;
      }

      const url = `${this.baseURL}${endpoint}`;
      
      console.log(`🔍 SkinBaron API Request to ${endpoint}:`, requestBody);

      const { statusCode, body } = await request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-requested-with': 'XMLHttpRequest',
          'User-Agent': 'SkinBaron-Alerts/1.0',
        },
        body: JSON.stringify(requestBody),
      });

      if (statusCode !== 200) {
        throw new Error(`SkinBaron API error: ${statusCode}`);
      }

      const rawData = await body.text();
      console.log(`📡 SkinBaron API Response from ${endpoint}:`, rawData.substring(0, 500));
      
      let jsonData;
      
      try {
        jsonData = JSON.parse(rawData);
      } catch (parseError) {
        console.error('Failed to parse SkinBaron response:', rawData);
        throw new Error('Invalid JSON response from SkinBaron API');
      }

      // Validate response with schema
      const validatedData = schema.parse(jsonData);
      
      return validatedData;
    } catch (error) {
      console.error(`❌ SkinBaron API Error (${endpoint}):`, error);
      throw error;
    }
  }



  /**
   * Search for items on SkinBaron
   */
  async search(params: SearchParams): Promise<{ items: SkinBaronItem[] }> {
    const searchData = {
      search_item: params.search_item,
      ...(params.min !== undefined && { min: params.min }),
      ...(params.max !== undefined && { max: params.max }),
      ...(params.statTrak !== undefined && { stattrak: params.statTrak }),
      ...(params.limit !== undefined && { items_per_page: params.limit }),
    };

    const result = await this.makeRequest(
      SKINBARON_API.ENDPOINTS.SEARCH,
      searchData,
      SearchResponseSchema
    );

    // Convert sales to items format for backward compatibility
    const items: SkinBaronItem[] = (result.sales || []).map(sale => ({
      saleId: sale.id,
      itemName: sale.market_name,
      price: sale.price,
      wearValue: sale.wear,
      statTrak: sale.stattrak,
      souvenir: sale.souvenir,
      sellerName: sale.seller,
      currency: sale.currency || 'EUR',
      quality: sale.quality,
      rarity: sale.rarity,
    }));

    return { items };
  }



  /**
   * Test API connection
   */
  async testConnection(): Promise<boolean> {
    try {
      // Simple search to test API connectivity
      await this.search({ 
        search_item: 'ak-47',
        limit: 1
      });
      return true;
    } catch (error) {
      console.error('❌ SkinBaron API connection test failed:', error);
      return false;
    }
  }

  /**
   * Generate SkinBaron listing URL
   */
  getSkinUrl(saleId: string): string {
    return `https://skinbaron.de/offers/show/${saleId}`;
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