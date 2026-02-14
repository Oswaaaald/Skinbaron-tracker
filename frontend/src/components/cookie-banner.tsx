'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import Link from 'next/link'

const COOKIE_NOTICE_KEY = 'cookie_notice_dismissed'

export function CookieBanner() {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    try {
      if (!localStorage.getItem(COOKIE_NOTICE_KEY)) {
        setVisible(true)
      }
    } catch {
      // localStorage unavailable (private browsing, storage full)
      setVisible(true)
    }
  }, [])

  const dismiss = () => {
    try {
      localStorage.setItem(COOKIE_NOTICE_KEY, '1')
    } catch {
      // localStorage unavailable — dismiss is still visual
    }
    setVisible(false)
  }

  if (!visible) return null

  return (
    <div
      role="status"
      aria-label="Cookie notice"
      className="fixed bottom-0 left-0 right-0 z-50 border-t bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 p-4 md:p-6"
    >
      <div className="container mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 max-w-4xl">
        <p className="text-sm text-muted-foreground">
          This site uses only essential cookies for authentication and security. No tracking or analytics cookies are used.{' '}
          <Link href="/privacy" className="underline hover:text-foreground">
            Privacy Policy
          </Link>
        </p>
        <Button size="sm" onClick={dismiss}>
          Got it
        </Button>
      </div>
    </div>
  )
}
