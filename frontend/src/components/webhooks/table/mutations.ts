'use client'

import type { Dispatch, SetStateAction } from 'react'
import { apiClient } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { useApiMutation } from '@/hooks/use-api-mutation'
import type { WebhookFormData } from '@/components/webhooks/table/types'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

interface UseWebhooksTableMutationsParams {
  syncStats: () => Promise<void>
  toast: ToastFn
  setSelectedWebhooks: Dispatch<SetStateAction<Set<number>>>
  setBatchAction: Dispatch<SetStateAction<'enable' | 'disable' | 'delete' | null>>
  setError: Dispatch<SetStateAction<string>>
  closeDialog: () => void
  resetForm: () => void
}

export function useWebhooksTableMutations({
  syncStats,
  toast,
  setSelectedWebhooks,
  setBatchAction,
  setError,
  closeDialog,
  resetForm,
}: UseWebhooksTableMutationsParams) {
  const createWebhookMutation = useApiMutation(
    (data: WebhookFormData) => apiClient.createWebhook(data),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      successMessage: 'Webhook created successfully',
      onSuccess: () => {
        closeDialog()
        setTimeout(resetForm, 200)
        void syncStats()
      },
      onError: (mutationError: Error) => {
        setError(mutationError.message)
      },
    }
  )

  const updateWebhookMutation = useApiMutation(
    ({ id, data }: { id: number; data: Partial<WebhookFormData> }) => apiClient.updateWebhook(id, data),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      successMessage: 'Webhook updated successfully',
      onSuccess: () => {
        closeDialog()
        setTimeout(resetForm, 200)
        void syncStats()
      },
      onError: (mutationError: Error) => {
        setError(mutationError.message)
      },
    }
  )

  const toggleActiveMutation = useApiMutation(
    ({ id, is_active }: { id: number; is_active: boolean }) => apiClient.updateWebhook(id, { is_active }),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      onSuccess: (_, { is_active }) => {
        toast({
          title: is_active ? '✅ Webhook enabled' : '⚠️ Webhook disabled',
          description: is_active ? 'Webhook is now active and will send notifications' : 'Webhook has been paused',
        })
        void syncStats()
      },
    }
  )

  const deleteWebhookMutation = useApiMutation(
    (id: number) => apiClient.deleteWebhook(id),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      successMessage: 'Webhook deleted successfully',
      errorMessage: 'Failed to delete webhook',
      onSuccess: () => {
        void syncStats()
      },
    }
  )

  const batchEnableMutation = useApiMutation(
    (webhookIds?: number[]) => apiClient.batchEnableWebhooks(webhookIds),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      successMessage: 'Webhooks enabled successfully',
      onSuccess: () => {
        setSelectedWebhooks(new Set())
        void syncStats()
      },
    }
  )

  const batchDisableMutation = useApiMutation(
    (webhookIds?: number[]) => apiClient.batchDisableWebhooks(webhookIds),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      successMessage: 'Webhooks disabled successfully',
      onSuccess: () => {
        setSelectedWebhooks(new Set())
        void syncStats()
      },
    }
  )

  const batchDeleteMutation = useApiMutation(
    ({ webhookIds, confirmAll }: { webhookIds?: number[]; confirmAll: boolean }) => apiClient.batchDeleteWebhooks(webhookIds, confirmAll),
    {
      invalidateKeys: [[QUERY_KEYS.WEBHOOKS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.USER_STATS]],
      onSuccess: () => {
        setBatchAction(null)
        void syncStats()
      },
      successMessage: 'Webhooks deleted successfully',
    }
  )

  return {
    createWebhookMutation,
    updateWebhookMutation,
    toggleActiveMutation,
    deleteWebhookMutation,
    batchEnableMutation,
    batchDisableMutation,
    batchDeleteMutation,
  }
}
