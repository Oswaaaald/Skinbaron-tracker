import { request } from 'undici';
import { z } from 'zod';
import { DISCORD_COLORS, appConfig } from './config.js';
import type { Rule, Alert } from './store.js';
import type { SkinBaronItem } from './sbclient.js';

// Discord Webhook Schemas
export const DiscordEmbedSchema = z.object({
  title: z.string().max(256),
  description: z.string().max(4096).optional(),
  url: z.string().url().optional(),
  color: z.number().optional(),
  timestamp: z.string().optional(),
  footer: z.object({
    text: z.string().max(2048),
    icon_url: z.string().url().optional(),
  }).optional(),
  thumbnail: z.object({
    url: z.string().url(),
  }).optional(),
  image: z.object({
    url: z.string().url(),
  }).optional(),
  fields: z.array(z.object({
    name: z.string().max(256),
    value: z.string().max(1024),
    inline: z.boolean().optional(),
  })).max(25).optional(),
});

export const DiscordWebhookPayloadSchema = z.object({
  username: z.string().max(80).optional(),
  avatar_url: z.string().url().optional(),
  content: z.string().max(2000).optional(),
  embeds: z.array(DiscordEmbedSchema).max(10).optional(),
});

export type DiscordEmbed = z.infer<typeof DiscordEmbedSchema>;
export type DiscordWebhookPayload = z.infer<typeof DiscordWebhookPayloadSchema>;

export interface NotificationOptions {
  alertType: 'match' | 'best_deal' | 'new_item';
  item: SkinBaronItem;
  rule?: Rule;
  skinUrl: string;
}

export class NotificationService {
  private readonly botName = appConfig.DISCORD_BOT_NAME;
  private readonly botAvatar = appConfig.DISCORD_BOT_AVATAR;

  constructor() {
  }

  /**
   * Send notification to Discord webhook
   */
  async sendNotification(
    webhookUrl: string, 
    options: NotificationOptions
  ): Promise<boolean> {
    try {
      const embed = this.createEmbed(options);
      const payload = this.createWebhookPayload(embed, options.alertType);

      // Validate payload
      const validatedPayload = DiscordWebhookPayloadSchema.parse(payload);

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(validatedPayload),
      });

      if (response.ok) {
        return true;
      } else {
        console.error(`❌ Discord webhook error: ${response.status}`);
        return false;
      }
    } catch (error) {
      console.error('❌ Failed to send Discord notification:', error);
      return false;
    }
  }

  /**
   * Create Discord embed for the notification
   */
  private createEmbed(options: NotificationOptions): DiscordEmbed {
    const { alertType, item, rule, skinUrl } = options;

    // Base embed structure
    const embed: DiscordEmbed = {
      title: this.getEmbedTitle(alertType, item),
      url: skinUrl,
      color: this.getEmbedColor(alertType),
      timestamp: new Date().toISOString(),
      footer: {
        text: 'SkinBaron Alerts • CS2 Skin Monitoring By Oswaaaald',
        icon_url: this.botAvatar,
      },
      fields: [],
    };

    // Add item details horizontally
    if (embed.fields) {
      embed.fields.push({
        name: '💰 Price',
        value: `${item.price} ${item.currency}`,
        inline: true,
      });

      if (item.wearValue !== undefined) {
        const wearPercentage = (item.wearValue * 100).toFixed(2);
        embed.fields.push({
          name: '🔍 Wear Value',
          value: `${wearPercentage}%`,
          inline: true,
        });
      }

      // StatTrak and Souvenir indicators
      const badges: string[] = [];
      if (item.statTrak) badges.push('🔥 StatTrak™');
      if (item.souvenir) badges.push('🏆 Souvenir');
      
      if (badges.length > 0) {
        embed.fields.push({
          name: '🏷️ Special',
          value: badges.join('\n'),
          inline: true,
        });
      }

      // Add action button after info
      embed.fields.push({
        name: '\u200B', // Invisible character for spacing
        value: `🎯 [**VIEW ON SKINBARON**](${skinUrl})`,
        inline: false,
      });
    }

    // Add item image (will appear at the bottom, closest to being "between" content and footer)
    if (item.imageUrl) {
      embed.image = {
        url: item.imageUrl,
      };
    }

    return embed;
  }

  /**
   * Create complete webhook payload
   */
  private createWebhookPayload(
    embed: DiscordEmbed, 
    alertType: 'match' | 'best_deal' | 'new_item'
  ): DiscordWebhookPayload {
    return {
      username: this.botName,
      avatar_url: this.botAvatar,
      content: this.getAlertMessage(alertType),
      embeds: [embed],
    };
  }

  /**
   * Get embed title based on alert type
   */
  private getEmbedTitle(alertType: 'match' | 'best_deal' | 'new_item', item: SkinBaronItem): string {
    const baseTitle = item.itemName;
    
    switch (alertType) {
      case 'match':
        return `🎯 Rule Match • ${baseTitle}`;
      case 'best_deal':
        return `💎 Best Deal • ${baseTitle}`;
      case 'new_item':
        return `🆕 New Item • ${baseTitle}`;
      default:
        return `🔔 Alert • ${baseTitle}`;
    }
  }

  /**
   * Get embed color based on alert type
   */
  private getEmbedColor(alertType: 'match' | 'best_deal' | 'new_item'): number {
    switch (alertType) {
      case 'match':
        return DISCORD_COLORS.MATCH;
      case 'best_deal':
        return DISCORD_COLORS.BEST_DEAL;
      case 'new_item':
        return DISCORD_COLORS.NEW_ITEM;
      default:
        return DISCORD_COLORS.MATCH;
    }
  }

  /**
   * Get alert message for content field
   */
  private getAlertMessage(alertType: 'match' | 'best_deal' | 'new_item'): string {
    switch (alertType) {
      case 'match':
        return '🎯 **Your alert rule matched a new item!**';
      case 'best_deal':
        return '💎 **New best deal available!**';
      case 'new_item':
        return '🆕 **Fresh item just listed!**';
      default:
        return '🔔 **New item alert!**';
    }
  }

  /**
   * Test webhook connection
   */
  async testWebhook(webhookUrl: string): Promise<boolean> {
    try {
      const testEmbed: DiscordEmbed = {
        title: '🧪 Test Notification',
        description: 'SkinBaron Alerts is working correctly!',
        color: DISCORD_COLORS.MATCH,
        timestamp: new Date().toISOString(),
        footer: {
          text: 'Test completed successfully',
        },
      };

      const payload: DiscordWebhookPayload = {
        username: this.botName,
        avatar_url: this.botAvatar,
        content: '✅ **Test notification from SkinBaron Alerts**',
        embeds: [testEmbed],
      };

      const { statusCode } = await request(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'SkinBaron-Alerts/1.0',
        },
        body: JSON.stringify(payload),
      });

      return statusCode === 204;
    } catch (error) {
      console.error('❌ Webhook test failed:', error);
      return false;
    }
  }

  /**
   * Send error notification
   */
  async sendErrorNotification(webhookUrl: string, error: string): Promise<boolean> {
    try {
      const errorEmbed: DiscordEmbed = {
        title: '⚠️ SkinBaron Alerts Error',
        description: `An error occurred while monitoring:\n\`\`\`${error}\`\`\``,
        color: DISCORD_COLORS.ERROR,
        timestamp: new Date().toISOString(),
        footer: {
          text: 'Error notification',
        },
      };

      const payload: DiscordWebhookPayload = {
        username: this.botName,
        avatar_url: this.botAvatar,
        content: '⚠️ **System Alert**',
        embeds: [errorEmbed],
      };

      const { statusCode } = await request(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'SkinBaron-Alerts/1.0',
        },
        body: JSON.stringify(payload),
      });

      return statusCode === 204;
    } catch (sendError) {
      console.error('❌ Failed to send error notification:', sendError);
      return false;
    }
  }

  /**
   * Format item for plain text display
   */
  formatItemText(item: SkinBaronItem): string {
    const parts = [item.itemName];
    
    if (item.statTrak) parts.push('StatTrak™');
    if (item.souvenir) parts.push('Souvenir');
    if (item.wearValue) parts.push(`Wear: ${(item.wearValue * 100).toFixed(2)}%`);
    
    parts.push(`${item.price} ${item.currency}`);
    
    return parts.join(' | ');
  }

  /**
   * Mask sensitive webhook URL for logging
   */
  private maskWebhook(webhookUrl: string): string {
    try {
      const url = new URL(webhookUrl);
      const pathParts = url.pathname.split('/');
      if (pathParts.length >= 3) {
        // Mask the webhook token (last part)
        pathParts[pathParts.length - 1] = '***';
        url.pathname = pathParts.join('/');
      }
      return url.toString();
    } catch {
      return 'invalid-webhook';
    }
  }
}

// Singleton instance
let notificationInstance: NotificationService | null = null;

export const getNotificationService = (): NotificationService => {
  if (!notificationInstance) {
    notificationInstance = new NotificationService();
  }
  return notificationInstance;
};

export default getNotificationService;