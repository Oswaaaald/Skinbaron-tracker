import { FastifyInstance } from 'fastify';
import { getSkinBaronClient } from '../lib/sbclient.js';
import { handleRouteError } from '../lib/validation-handler.js';

export default async function itemsRoutes(fastify: FastifyInstance) {
  
  // All routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);
  
  // Rate limiting for item search (protect SkinBaron API quota)
  const searchRateLimitConfig = {
    max: 30,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many requests',
      message: 'You are searching too fast. Please wait a moment.',
    }),
  };

  // Search items endpoint for autocomplete
  fastify.get('/search', {
    config: {
      rateLimit: searchRateLimitConfig,
    },
    schema: {
      description: 'Search SkinBaron items for autocomplete',
      tags: ['Items'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Search query' },
          limit: { type: 'string', description: 'Max results (default: 20, max: 50)' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  classId: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { q, limit } = request.query as { q?: string; limit?: string };
      
      if (!q || q.trim().length === 0) {
        return reply.status(200).send({
          success: true,
          data: [],
        });
      }

      // Limit results for autocomplete (max 20 suggestions)
      const maxResults = Math.min(parseInt(limit || '20', 10), 50);

      const skinBaronClient = getSkinBaronClient();
      const result = await skinBaronClient.search({
        search_item: q.trim(),
        limit: maxResults,
      });

      // Helper function to clean item name - remove StatTrak, Souvenir, and wear conditions
      const cleanItemName = (name: string): string => {
        let cleaned = name;
        
        // Remove StatTrak™ prefix
        cleaned = cleaned.replace(/^StatTrak™\s+/i, '');
        
        // Remove Souvenir prefix
        cleaned = cleaned.replace(/^Souvenir\s+/i, '');
        
        // Remove wear conditions in parentheses
        cleaned = cleaned.replace(/\s*\((Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\)\s*$/i, '');
        
        return cleaned.trim();
      };

      // Extract unique item names for autocomplete suggestions
      const uniqueNames = new Set<string>();
      const suggestions = result.items
        .map(item => {
          // Clean the item name to remove StatTrak, Souvenir, and wear conditions
          const cleanName = cleanItemName(item.itemName);
          if (!uniqueNames.has(cleanName)) {
            uniqueNames.add(cleanName);
            return {
              name: cleanName,
              imageUrl: item.imageUrl,
            };
          }
          return null;
        })
        .filter((item): item is { name: string; imageUrl: string | undefined } => item !== null)
        .slice(0, maxResults);

      return reply.status(200).send({
        success: true,
        data: suggestions,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Search items');
    }
  });
}
