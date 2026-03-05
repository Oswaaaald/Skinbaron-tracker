'use client'

import { useEffect } from 'react'
import * as Sentry from '@sentry/nextjs'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertCircle, RefreshCw, ArrowLeft } from 'lucide-react'
import Link from 'next/link'

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error('Dashboard error:', error)
    if (process.env['NEXT_PUBLIC_SENTRY_DSN']) Sentry.captureException(error)
  }, [error])

  return (
    <div className="mx-auto flex min-h-[70vh] w-full max-w-7xl items-center justify-center px-4 py-8 sm:px-6">
      <Card className="w-full max-w-md border-border/70 bg-card/95 py-0">
        <CardHeader className="space-y-4 border-b border-border/65 pb-5 text-center">
          <span className="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-lg border border-destructive/30 bg-destructive/10 text-destructive">
            <AlertCircle className="h-5 w-5" />
          </span>
          <div className="space-y-1.5">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Dashboard error</p>
            <CardTitle className="text-2xl tracking-tight">Something went wrong</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 p-5">
          <p className="text-center text-sm text-muted-foreground">
            An error occurred while loading this page. Please try again or return to the dashboard.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Button variant="outline" asChild className="w-full">
              <Link href="/alerts">
                <ArrowLeft className="h-4 w-4 mr-2" aria-hidden="true" />
                Dashboard
              </Link>
            </Button>
            <Button onClick={reset} className="w-full">
              <RefreshCw className="h-4 w-4 mr-2" aria-hidden="true" />
              Try Again
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
