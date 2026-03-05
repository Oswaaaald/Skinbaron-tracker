'use client'

import type { UseFormReturn } from 'react-hook-form'
import { Button } from '@/components/ui/button'
import { DialogFooter } from '@/components/ui/dialog'
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Switch } from '@/components/ui/switch'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import type { RuleFormData } from '@/components/rules/dialog/schema'

interface RuleDialogWebhookAndStatusProps {
  form: UseFormReturn<RuleFormData>
  webhooks: Array<{ id?: number | null; name: string; webhook_type?: string }>
  selectedWebhooks: number[]
  isSubmitting: boolean
  isEditing: boolean
  onOpenChange: (open: boolean) => void
  onWebhookToggle: (webhookId: number) => void
  getSelectedWebhookNames: () => string
}

export function RuleDialogWebhookAndStatus({
  form,
  webhooks,
  selectedWebhooks,
  isSubmitting,
  isEditing,
  onOpenChange,
  onWebhookToggle,
  getSelectedWebhookNames,
}: RuleDialogWebhookAndStatusProps) {
  return (
    <>
      <FormField
        control={form.control}
        name="webhook_ids"
        render={() => (
          <FormItem>
            <FormLabel>Notification Webhooks (Optional - Max 10)</FormLabel>
            <FormDescription className="mb-3">
              Select which webhooks should receive notifications for this rule. Leave empty to create a rule without notifications.
            </FormDescription>

            {!webhooks || webhooks.length === 0 ? (
              <div className="text-center py-4 text-muted-foreground">
                {!webhooks
                  ? 'Loading webhooks...'
                  : 'No webhooks configured. You can create a rule without notifications or add webhooks in the Webhooks section.'}
              </div>
            ) : (
              <div className="space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
                {webhooks.filter((webhook) => webhook.id != null).map((webhook) => (
                  <div
                    key={webhook.id}
                    className="flex items-center space-x-2 p-2 rounded border hover:bg-muted cursor-pointer"
                    onClick={() => onWebhookToggle(webhook.id as number)}
                  >
                    <input
                      type="checkbox"
                      checked={selectedWebhooks.includes(webhook.id as number)}
                      onChange={() => onWebhookToggle(webhook.id as number)}
                      className="h-4 w-4"
                      aria-label={`Select webhook ${webhook.name}`}
                    />
                    <span className="flex-1 text-sm">{webhook.name}</span>
                    <span className="text-xs text-muted-foreground">
                      {webhook.webhook_type === 'discord' ? '🎮 Discord' : '🔗 Other'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {selectedWebhooks.length > 0 && (
              <div className="mt-2 p-2 bg-muted rounded text-sm">
                <strong>Selected:</strong> {getSelectedWebhookNames()}
              </div>
            )}

            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={form.control}
        name="enabled"
        render={({ field }) => (
          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <FormLabel>Enable Rule</FormLabel>
              <FormDescription>Rule will be active and send notifications</FormDescription>
            </div>
            <FormControl>
              <Switch checked={field.value} onCheckedChange={field.onChange} disabled={isSubmitting} />
            </FormControl>
          </FormItem>
        )}
      />

      <DialogFooter>
        <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
          Cancel
        </Button>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? (
            <>
              <LoadingSpinner size="sm" className="mr-2" inline />
              {isEditing ? 'Updating...' : 'Creating...'}
            </>
          ) : (
            <>{isEditing ? 'Update Rule' : 'Create Rule'}</>
          )}
        </Button>
      </DialogFooter>
    </>
  )
}
