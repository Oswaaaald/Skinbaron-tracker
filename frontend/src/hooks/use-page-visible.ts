import { useEffect, useState } from 'react'

// Lightweight page visibility hook to pause background polling when the tab is hidden
export function usePageVisible() {
  // Always initialise as true to avoid SSR/client hydration mismatch (#418).
  // The useEffect below will sync the real value immediately on mount.
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsVisible(document.visibilityState === 'visible')
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange)
  }, [])

  return isVisible
}
