'use client'

import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { usePageVisible } from '@/hooks/use-page-visible'
import { toast } from '@/hooks/use-toast'
import { POLL_INTERVAL, QUERY_KEYS } from '@/lib/constants'

/**
 * Polls alert stats and shows a toast when new alerts arrive.
 * Must be mounted at dashboard layout level so it works on every page.
 */
export function useAlertNotifier() {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()
  const prevTotal = useRef<number | null>(null)

  const { data } = useQuery({
    queryKey: [QUERY_KEYS.ALERT_STATS],
    queryFn: async () =>
      apiClient.ensureSuccess(
        await apiClient.getAlertStats(),
        'Failed to load alert stats',
      ),
    enabled: isReady && isAuthenticated,
    staleTime: POLL_INTERVAL,
    refetchInterval: isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
    notifyOnChangeProps: ['data'],
  })

  const totalAlerts = data?.data?.totalAlerts

  useEffect(() => {
    if (totalAlerts === undefined) return

    // First load — seed the baseline without toasting
    if (prevTotal.current === null) {
      prevTotal.current = totalAlerts
      return
    }

    const diff = totalAlerts - prevTotal.current
    if (diff > 0) {
      toast({
        title: '🔔 New alerts',
        description:
          diff === 1
            ? '1 new alert has been triggered'
            : `${diff} new alerts have been triggered`,
      })
    }

    prevTotal.current = totalAlerts
  }, [totalAlerts])
}
