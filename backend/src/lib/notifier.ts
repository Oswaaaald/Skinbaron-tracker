import { z } from 'zod';
import { DISCORD_COLORS, appConfig } from './config.js';
import type { Rule } from '../database/schemas.js';
import type { SkinBaronItem } from './sbclient.js';
import pino from 'pino';

// Discord Webhook Schemas (internal)
const DiscordEmbedSchema = z.object({
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

const DiscordWebhookPayloadSchema = z.object({
  username: z.string().max(80).optional(),
  avatar_url: z.string().url().optional(),
  content: z.string().max(2000).optional(),
  embeds: z.array(DiscordEmbedSchema).max(10).optional(),
});

type DiscordEmbed = z.infer<typeof DiscordEmbedSchema>;
type DiscordWebhookPayload = z.infer<typeof DiscordWebhookPayloadSchema>;

export type NotificationStyle = 'compact' | 'detailed';

interface NotificationOptions {
  item: SkinBaronItem;
  rule?: Rule;
  skinUrl: string;
  style?: NotificationStyle;
}

export class NotificationService {
  private readonly botName = appConfig.DISCORD_BOT_NAME;
  private readonly botAvatar = appConfig.DISCORD_BOT_AVATAR;
  private readonly logger = pino({ level: appConfig.LOG_LEVEL });

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

      // AbortController for timeout (10 seconds)
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(validatedPayload),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        return true;
      } else {
        const errorBody = await response.text().catch(() => 'Unable to read response body');
        this.logger.error({ status: response.status, errorBody }, '[Notifier] Discord webhook failed');
        return false;
      }
    } catch (error) {
      this.logger.error({ error: error instanceof Error ? error.message : error }, '[Notifier] Discord webhook error');
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
      : '🔍 **No Wear**';

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
    ];

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
      } else {
        embed.fields.push({
          name: '🔍 Wear',
          value: '**No Wear**',
          inline: true,
        });
      }

      // Spacer for alignment
      embed.fields.push({
        name: '\u200B',
        value: '\u200B',
        inline: true,
      });

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
}

// Singleton instance
let notificationInstance: NotificationService | null = null;

export const getNotificationService = (): NotificationService => {
  if (!notificationInstance) {
    notificationInstance = new NotificationService();
  }
  return notificationInstance;
};