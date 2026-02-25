'use client'

import { useState, useSyncExternalStore } from 'react'
import { Button } from '@/components/ui/button'
import Link from 'next/link'

const COOKIE_NOTICE_KEY = 'cookie_notice_dismissed'

function subscribeToCookieNotice(callback: () => void) {
  window.addEventListener('storage', callback)
  return () => window.removeEventListener('storage', callback)
}

function getCookieNoticeSnapshot() {
  try {
    return !localStorage.getItem(COOKIE_NOTICE_KEY)
  } catch {
    return true
  }
}

function getCookieNoticeServerSnapshot() {
  return false // SSR: assume dismissed to avoid hydration flash
}

export function CookieBanner() {
  const shouldShow = useSyncExternalStore(
    subscribeToCookieNotice,
    getCookieNoticeSnapshot,
    getCookieNoticeServerSnapshot,
  )
  const [dismissed, setDismissed] = useState(false)
  const visible = shouldShow && !dismissed

  const dismiss = () => {
    try {
      localStorage.setItem(COOKIE_NOTICE_KEY, '1')
    } catch { /* ignore */ }
    setDismissed(true)
  }

  if (!visible) return null

  return (
    <div
      role="status"
      aria-label="Cookie notice"
      className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-4 sm:max-w-sm z-50 rounded-lg border border-border/60 bg-background/95 backdrop-blur-lg shadow-lg p-4"
    >
      <p className="text-xs leading-relaxed text-muted-foreground mb-3">
        This site uses essential cookies only for authentication and security. No tracking or analytics.{' '}
        <Link href="/privacy" className="underline underline-offset-2 hover:text-foreground transition-colors">
          Privacy policy
        </Link>
      </p>
      <Button size="sm" className="w-full" onClick={dismiss}>
        Got it
      </Button>
    </div>
  )
}
