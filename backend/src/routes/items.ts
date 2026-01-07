import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { getSkinBaronClient } from '../lib/sbclient.js';

export default async function itemsRoutes(fastify: FastifyInstance) {
  // Search items endpoint for autocomplete
  fastify.get('/search', async (request: FastifyRequest, reply: FastifyReply) => {
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
      request.log.error({ error }, 'Failed to search items');
      return reply.status(500).send({
        success: false,
        error: 'Failed to search items',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}
