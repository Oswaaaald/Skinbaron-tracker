import { z } from 'zod';
import { DISCORD_COLORS, appConfig } from './config.js';
import type { Rule } from '../database/schemas.js';
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

export type NotificationStyle = 'compact' | 'detailed';

export interface NotificationOptions {
  item: SkinBaronItem;
  rule?: Rule;
  skinUrl: string;
  style?: NotificationStyle;
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
      const style = options.style || 'compact';
      const embed = style === 'detailed'
        ? this.createDetailedEmbed(options)
        : this.createCompactEmbed(options);
      const payload = this.createWebhookPayload(embed);

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
        return false;
      }
    } catch {
      return false;
    }
  }

  /**
   * Create compact Discord embed (thumbnail + description)
   */
  private createCompactEmbed(options: NotificationOptions): DiscordEmbed {
    const { item, skinUrl } = options;

    const price = `${item.price.toFixed(2).replace('.', ',')} €`;
    const wearLine = item.wearValue !== undefined
      ? `🔍 **Wear:** ${(item.wearValue * 100).toFixed(2)} %`
      : null;

    // Separate badge lines
    const badgeLines: string[] = [];
    if (item.statTrak) badgeLines.push('⭐ **StatTrak™**');
    if (item.souvenir) badgeLines.push('🏆 **Souvenir**');
    if (item.hasStickers) badgeLines.push('🏷️ **Stickers**');

    // Compose description block
    const descriptionParts = [
      `💰 **${price}**`,
      wearLine,
      ...badgeLines,
      '',
      `🔗 [**View on SkinBaron**](${skinUrl})`,
    ].filter((line): line is string => line !== null);

    const embed: DiscordEmbed = {
      title: item.itemName,
      url: skinUrl,
      description: descriptionParts.join('\n'),
      color: DISCORD_COLORS.MATCH,
      timestamp: new Date().toISOString(),
      footer: {
        text: 'SkinBaron Tracker • CS2 Skin Monitoring By Oswaaaald',
        icon_url: this.botAvatar,
      },
    };

    if (item.imageUrl) {
      embed.thumbnail = {
        url: item.imageUrl,
      };
    }

    return embed;
  }

  /**
   * Create detailed Discord embed (fields + large image)
   */
  private createDetailedEmbed(options: NotificationOptions): DiscordEmbed {
    const { item, skinUrl } = options;

    const embed: DiscordEmbed = {
      title: item.itemName,
      url: skinUrl,
      color: DISCORD_COLORS.MATCH,
      timestamp: new Date().toISOString(),
      footer: {
        text: 'SkinBaron Tracker • CS2 Skin Monitoring By Oswaaaald',
        icon_url: this.botAvatar,
      },
      fields: [],
    };

    if (embed.fields) {
      // Price field
      embed.fields.push({
        name: '💰 Price',
        value: `**${item.price.toFixed(2).replace('.', ',')} €**`,
        inline: true,
      });

      // Wear field
      if (item.wearValue !== undefined) {
        embed.fields.push({
          name: '🔍 Wear',
          value: `**${(item.wearValue * 100).toFixed(2)} %**`,
          inline: true,
        });
      }

      // Spacer for alignment
      if (item.wearValue !== undefined) {
        embed.fields.push({
          name: '\u200B',
          value: '\u200B',
          inline: true,
        });
      }

      // Individual badge fields on separate lines
      if (item.statTrak) {
        embed.fields.push({
          name: '⭐ StatTrak™',
          value: '\u200B',
          inline: true,
        });
      }

      if (item.souvenir) {
        embed.fields.push({
          name: '🏆 Souvenir',
          value: '\u200B',
          inline: true,
        });
      }

      if (item.hasStickers) {
        embed.fields.push({
          name: '🏷️ Stickers',
          value: '\u200B',
          inline: true,
        });
      }

      // View button
      embed.fields.push({
        name: '\u200B',
        value: `🔗 [**View on SkinBaron**](${skinUrl})`,
        inline: false,
      });
    }

    // Large image at the bottom
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
    embed: DiscordEmbed
  ): DiscordWebhookPayload {
    return {
      username: this.botName,
      avatar_url: this.botAvatar,
      content: '🎯 **Your alert rule matched a new item!**',
      embeds: [embed],
    };
  }

  /**
   * Test webhook connection
   */
  async testWebhook(webhookUrl: string): Promise<boolean> {
    try {
      const testEmbed: DiscordEmbed = {
        title: '🧪 Test Notification',
        description: 'SkinBaron Tracker is working correctly!',
        color: DISCORD_COLORS.MATCH,
        timestamp: new Date().toISOString(),
        footer: {
          text: 'Test completed successfully',
        },
      };

      const payload: DiscordWebhookPayload = {
        username: this.botName,
        avatar_url: this.botAvatar,
        content: '✅ **Test notification from SkinBaron Tracker**',
        embeds: [testEmbed],
      };

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'SkinBaron-Tracker/1.0',
        },
        body: JSON.stringify(payload),
      });

      return response.status === 204;
    } catch {
      return false;
    }
  }

  /**
   * Send error notification
   */
  async sendErrorNotification(webhookUrl: string, error: string): Promise<boolean> {
    try {
      const errorEmbed: DiscordEmbed = {
        title: '⚠️ SkinBaron Tracker Error',
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

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'SkinBaron-Tracker/1.0',
        },
        body: JSON.stringify(payload),
      });

      return response.status === 204;
    } catch {
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