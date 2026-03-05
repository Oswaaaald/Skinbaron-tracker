'use client'

import * as Sentry from '@sentry/nextjs'
import { useEffect } from 'react'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    if (process.env['NEXT_PUBLIC_SENTRY_DSN']) Sentry.captureException(error)
  }, [error])

  return (
    <html lang="en" suppressHydrationWarning>
      <body className="bg-background text-foreground antialiased">
        <div className="flex min-h-screen items-center justify-center px-4 py-12">
          <div className="w-full max-w-md rounded-2xl border border-border/70 bg-card/95 p-6 text-center shadow-sm">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Critical error</p>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight">Something went wrong</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              An unexpected error occurred while rendering the app shell.
            </p>
            <button
              onClick={reset}
              className="mt-5 inline-flex h-10 items-center justify-center rounded-lg border border-border/70 px-4 text-sm font-medium hover:bg-muted/60"
            >
              Try again
            </button>
          </div>
        </div>
      </body>
    </html>
  )
}
