'use client'

import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { usePageVisible } from '@/hooks/use-page-visible'
import { toast } from '@/hooks/use-toast'
import { POLL_INTERVAL, QUERY_KEYS } from '@/lib/constants'

const LAST_SEEN_KEY = 'alert_notifier_last_total'

/**
 * Polls alert stats and shows a toast when new alerts arrive.
 * Persists the last-seen count in localStorage so that alerts received
 * while the user was away are shown on next login.
 * Must be mounted at dashboard layout level so it works on every page.
 */
export function useAlertNotifier() {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()
  const prevTotal = useRef<number | null>(null)
  const initialised = useRef(false)

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

    // First fetch — restore baseline from localStorage (survives logout/close)
    if (!initialised.current) {
      initialised.current = true
      const stored = localStorage.getItem(LAST_SEEN_KEY)
      const lastSeen = stored !== null ? Number(stored) : null

      if (lastSeen !== null && !Number.isNaN(lastSeen)) {
        const diff = totalAlerts - lastSeen
        if (diff > 0) {
          toast({
            title: '🔔 New alerts',
            description:
              diff === 1
                ? '1 new alert since your last visit'
                : `${diff} new alerts since your last visit`,
          })
        }
      }

      prevTotal.current = totalAlerts
      localStorage.setItem(LAST_SEEN_KEY, String(totalAlerts))
      return
    }

    // Subsequent polls — compare with previous value
    const diff = totalAlerts - (prevTotal.current ?? 0)
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
    localStorage.setItem(LAST_SEEN_KEY, String(totalAlerts))
  }, [totalAlerts])
}
