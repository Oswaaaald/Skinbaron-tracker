'use client'

import type { Dispatch, SetStateAction } from 'react'
import type { Rule } from '@/lib/api'
import { apiClient } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'
import { useApiMutation } from '@/hooks/use-api-mutation'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

interface UseRulesTableMutationsParams {
  syncStats: () => Promise<void>
  toast: ToastFn
  setSelectedRules: Dispatch<SetStateAction<Set<number>>>
}

export function useRulesTableMutations({ syncStats, toast, setSelectedRules }: UseRulesTableMutationsParams) {
  const toggleRuleMutation = useApiMutation(
    ({ rule, enabled }: { rule: Rule; enabled: boolean }) => {
      if (!rule.id) throw new Error('Rule ID is required')
      return apiClient.updateRule(rule.id, { enabled })
    },
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (_, { enabled }) => {
        toast({
          title: enabled ? '✅ Rule enabled' : '⚠️ Rule disabled',
          description: enabled ? 'Rule is now active and monitoring items' : 'Rule has been paused',
        })
        void syncStats()
      },
      onError: (mutationError: unknown) => {
        toast({ variant: 'destructive', title: '❌ Failed to update rule', description: extractErrorMessage(mutationError) })
      },
    }
  )

  const deleteRuleMutation = useApiMutation(
    (id: number) => apiClient.deleteRule(id),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: () => {
        toast({ title: '✅ Rule deleted', description: 'The monitoring rule has been permanently deleted' })
        void syncStats()
      },
      onError: (mutationError: unknown) => {
        toast({ variant: 'destructive', title: '❌ Failed to delete rule', description: extractErrorMessage(mutationError) })
      },
    }
  )

  const batchEnableMutation = useApiMutation(
    (ruleIds?: number[]) => apiClient.batchEnableRules(ruleIds),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (data) => {
        toast({ title: '✅ Rules enabled', description: `${data?.count || 0} rule(s) have been enabled` })
        setSelectedRules(new Set())
        void syncStats()
      },
      onError: (mutationError: unknown) => {
        toast({ variant: 'destructive', title: '❌ Failed to enable rules', description: extractErrorMessage(mutationError) })
      },
    }
  )

  const batchDisableMutation = useApiMutation(
    (ruleIds?: number[]) => apiClient.batchDisableRules(ruleIds),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (data) => {
        toast({ title: '⚠️ Rules disabled', description: `${data?.count || 0} rule(s) have been disabled` })
        setSelectedRules(new Set())
        void syncStats()
      },
      onError: (mutationError: unknown) => {
        toast({ variant: 'destructive', title: '❌ Failed to disable rules', description: extractErrorMessage(mutationError) })
      },
    }
  )

  const batchDeleteMutation = useApiMutation(
    ({ ruleIds, confirmAll }: { ruleIds?: number[]; confirmAll: boolean }) => apiClient.batchDeleteRules(ruleIds, confirmAll),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (data) => {
        toast({ title: '✅ Rules deleted', description: `${data?.count || 0} rule(s) have been permanently deleted` })
        setSelectedRules(new Set())
        void syncStats()
      },
      onError: (mutationError: unknown) => {
        toast({ variant: 'destructive', title: '❌ Failed to delete rules', description: extractErrorMessage(mutationError) })
      },
    }
  )

  return {
    toggleRuleMutation,
    deleteRuleMutation,
    batchEnableMutation,
    batchDisableMutation,
    batchDeleteMutation,
  }
}
