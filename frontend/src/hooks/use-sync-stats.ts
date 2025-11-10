"use client"

import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'

/**
 * Hook to synchronize statistics across components
 * Forces immediate refresh of stats when alerts change
 */
export function useSyncStats() {
  const queryClient = useQueryClient()

  const syncStats = async () => {
    // Force immediate refetch instead of just invalidating
    await Promise.all([
      queryClient.refetchQueries({ queryKey: ['alert-stats'] }),
      queryClient.refetchQueries({ queryKey: ['system-status'] })
    ])
  }

  return { syncStats }
}