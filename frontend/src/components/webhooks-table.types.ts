export interface WebhookFormData {
  name: string
  webhook_url: string
  notification_style: 'compact' | 'detailed'
  is_active: boolean
}

export const initialWebhookFormData: WebhookFormData = {
  name: '',
  webhook_url: '',
  notification_style: 'compact',
  is_active: true,
}
