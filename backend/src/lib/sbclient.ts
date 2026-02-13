import { request } from 'undici';
import { z } from 'zod';
import { appConfig, SKINBARON_API } from './config.js';

// SkinBaron API Response Schemas (internal)
const SkinBaronSaleSchema = z.object({
  id: z.string(),
  price: z.number(),
  img: z.string().optional(),
  market_name: z.string(),
  sbinspect: z.string().optional(),
  inspect: z.string().optional(),
  stickers: z.string().optional(),
  wear: z.number().optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  seller: z.string().optional(),
  currency: z.string().optional(),
  quality: z.string().optional(),
  rarity: z.string().optional(),
  appid: z.number().optional(),
});

const SearchResponseSchema = z.object({
  sales: z.array(SkinBaronSaleSchema).optional(),
});


// Legacy type for backward compatibility - we'll adapt sales to items
export interface SkinBaronItem {
  saleId: string;
  itemName: string;
  price: number;
  wearValue?: number;
  statTrak?: boolean;
  souvenir?: boolean;
  hasStickers?: boolean; // True if item has stickers applied
  stickersData?: string; // Raw stickers data from API
  sellerName?: string;
  currency?: string;
  quality?: string;
  rarity?: string;
  skinUrl?: string; // URL vers l'offre SkinBaron
  imageUrl?: string; // URL de l'image Steam de l'item
}

// Search parameters
interface SearchParams {
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
    params: Record<string, string | number | boolean> = {}, 
    schema: z.ZodSchema<T>,
    retryCount: number = 0
  ): Promise<T> {
    const MAX_RETRIES = 3;
    const RETRY_DELAYS = [2000, 5000, 10000]; // 2s, 5s, 10s backoff
    
    try {
      const requestBody: Record<string, string | number | boolean> = {
        appid: this.appId,
        ...params,
      };

      // Only add API key if provided
      if (this.apiKey) {
        requestBody['apikey'] = this.apiKey;
      }

      const url = `${this.baseURL}${endpoint}`;

      const { statusCode, body } = await request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-requested-with': 'XMLHttpRequest',
          'User-Agent': 'SkinBaron-Tracker/1.0',
        },
        body: JSON.stringify(requestBody),
      });

      // Handle rate limiting with retry
      if (statusCode === 429) {
        if (retryCount < MAX_RETRIES) {
          const delay = RETRY_DELAYS[retryCount];
          await new Promise(resolve => setTimeout(resolve, delay));
          return this.makeRequest(endpoint, params, schema, retryCount + 1);
        }
        throw new Error(`SkinBaron API rate limit exceeded after ${MAX_RETRIES} retries`);
      }

      // Handle authentication errors (don't retry these)
      if (statusCode === 401 || statusCode === 403) {
        throw new Error(`SkinBaron API authentication failed: Invalid or missing API key (${statusCode})`);
      }

      if (statusCode !== 200) {
        throw new Error(`SkinBaron API error: ${statusCode}`);
      }

      const rawData = await body.text();
      let jsonData: unknown;
      
      try {
        jsonData = JSON.parse(rawData) as unknown;
      } catch {
        throw new Error('Invalid JSON response from SkinBaron API');
      }

      // Validate response with schema
      const validatedData = schema.parse(jsonData);
      
      return validatedData;
    } catch (error) {
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
    const items: SkinBaronItem[] = (result.sales || []).map(sale => {
      // Améliorer la détection StatTrak - toujours utiliser le nom pour plus de fiabilité
      const isStatTrak = sale.market_name.includes('StatTrak™');
      const isSouvenir = sale.market_name.includes('Souvenir');
      
      // Check if item has stickers applied (stickers field is non-empty)
      const hasStickers = !!(sale.stickers && sale.stickers.trim().length > 0);
      
      return {
        saleId: sale.id,
        itemName: sale.market_name,
        price: sale.price,
        wearValue: sale.wear,
        statTrak: isStatTrak, // Toujours basé sur le nom pour plus de fiabilité
        souvenir: isSouvenir, // Toujours basé sur le nom pour plus de fiabilité
        hasStickers: hasStickers, // True if item has stickers applied
        stickersData: sale.stickers, // Raw stickers data
        sellerName: sale.seller,
        currency: sale.currency || 'EUR',
        quality: sale.quality,
        rarity: sale.rarity,
        skinUrl: sale.sbinspect || this.getSkinUrl(sale.id), // Utiliser sbinspect si disponible
        imageUrl: sale.img, // URL de l'image Steam
      };
    });

    return { items };
  }



  private lastConnectionTest: { timestamp: number; result: boolean } | null = null;
  private readonly CONNECTION_TEST_CACHE_MS = 300000; // Cache for 5 minutes (sync with scheduler)

  /**
   * Test API connection (with caching to avoid excessive calls)
   */
  async testConnection(): Promise<boolean> {
    const now = Date.now();
    
    // Use cached result if less than 1 minute old
    if (this.lastConnectionTest && 
        (now - this.lastConnectionTest.timestamp) < this.CONNECTION_TEST_CACHE_MS) {
      return this.lastConnectionTest.result;
    }

    try {
      // Test with a minimal search (works for both public and authenticated access)
      await this.search({ 
        search_item: 'AK-47',
        limit: 1
      });
      
      this.lastConnectionTest = { timestamp: now, result: true };
      return true;
    } catch (error) {
      // Log the specific error for debugging
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('[SkinBaron] Connection test failed:', errorMessage);
      
      this.lastConnectionTest = { timestamp: now, result: false };
      return false;
    }
  }

  /**
   * Generate SkinBaron listing URL (fallback si sbinspect non disponible)
   */
  getSkinUrl(saleId: string, itemName?: string): string {
    if (itemName) {
      const productName = itemName.replace(/StatTrak™\s+/, '').replace(/Souvenir\s+/, '');
      const encodedProductName = encodeURIComponent(productName);
      return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodedProductName}`;
    }
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}`;
  }

    /**
   * Check if an item matches the given search parameters
   */
  matchesFilters(item: SkinBaronItem, params: SearchParams): boolean {
    if (params.statTrak !== undefined) {
      const itemIsStatTrak = item.statTrak || item.itemName.includes('StatTrak™');
      if (itemIsStatTrak !== params.statTrak) {
        return false;
      }
    }

    if (params.souvenir !== undefined) {
      const itemIsSouvenir = item.souvenir || item.itemName.includes('Souvenir');
      if (itemIsSouvenir !== params.souvenir) {
        return false;
      }
    }

    if (params.min !== undefined && params.min !== null && item.price < params.min) {
      return false;
    }

    if (params.max !== undefined && params.max !== null && item.price > params.max) {
      return false;
    }

    if (params.minWear !== undefined && params.minWear !== null && item.wearValue && item.wearValue < params.minWear) {
      return false;
    }

    if (params.maxWear !== undefined && params.maxWear !== null && item.wearValue && item.wearValue > params.maxWear) {
      return false;
    }

    return true;
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