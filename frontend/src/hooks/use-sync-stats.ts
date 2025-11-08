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
    try {
      console.log('🔄 Starting stats sync...')
      
      // Method 1: Remove cached data completely
      queryClient.removeQueries({ queryKey: ['alert-stats'] })
      queryClient.removeQueries({ queryKey: ['system-status'] })
      
      // Method 2: Force immediate refetch  
      await Promise.all([
        queryClient.refetchQueries({ queryKey: ['alert-stats'], type: 'active' }),
        queryClient.refetchQueries({ queryKey: ['system-status'], type: 'active' })
      ])
      
      console.log('✅ Stats synced successfully')
    } catch (error) {
      console.error('❌ Failed to sync stats:', error)
    }
  }

  return { syncStats }
}