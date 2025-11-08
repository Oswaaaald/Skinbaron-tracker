"use client"

import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'

/**
 * Hook to synchronize statistics across components
 * Forces immediate refresh of stats when alerts change
 */
export function useSyncStats() {
  const queryClient = useQueryClient()

  const syncStats = () => {
    // Force immediate refresh of all stats
    queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
    queryClient.invalidateQueries({ queryKey: ['system-status'] })
    
    // Also force refetch to ensure immediate update
    queryClient.refetchQueries({ queryKey: ['alert-stats'] })
    queryClient.refetchQueries({ queryKey: ['system-status'] })
  }

  return { syncStats }
}