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
    console.log('🔄 Invalidating stats cache...')
    
    // Simple invalidation - let the auto-refresh (10s interval) handle the rest
    queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
    queryClient.invalidateQueries({ queryKey: ['system-status'] })
    
    console.log('✅ Stats cache invalidated - auto-refresh will update in max 10s')
  }

  return { syncStats }
}