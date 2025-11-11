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
    console.log('🔄 Syncing all statistics (alert-stats, system-status, user-stats)...')
    
    // Force immediate refetch instead of just invalidating
    await Promise.all([
      queryClient.refetchQueries({ queryKey: ['alert-stats'] }),
      queryClient.refetchQueries({ queryKey: ['system-status'] }),
      queryClient.refetchQueries({ queryKey: ['user-stats'] }) // Add user stats for dashboard sync
    ])
    
    console.log('✅ All statistics synced immediately!')
  }

  return { syncStats }
}