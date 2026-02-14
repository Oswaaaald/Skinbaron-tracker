"use client"

import { useQueryClient } from '@tanstack/react-query'
import { QUERY_KEYS } from '@/lib/constants'

/**
 * Hook to synchronize statistics across components
 * Forces immediate refresh of stats when data changes (alerts, rules, webhooks)
 */
export function useSyncStats() {
  const queryClient = useQueryClient()

  const syncStats = async () => {
    // Force immediate refetch of all stat-related queries
    await Promise.all([
      queryClient.refetchQueries({ queryKey: [QUERY_KEYS.ALERT_STATS] }),
      queryClient.refetchQueries({ queryKey: [QUERY_KEYS.SYSTEM_STATUS] }),
      queryClient.refetchQueries({ queryKey: [QUERY_KEYS.USER_STATS] }),
      queryClient.refetchQueries({ queryKey: [QUERY_KEYS.ADMIN_STATS] }),
    ])
  }

  return { syncStats }
}