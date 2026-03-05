'use client'

import * as Sentry from '@sentry/nextjs'
import { useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { AlertCircle, Home } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import Link from 'next/link'

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    if (process.env['NEXT_PUBLIC_SENTRY_DSN']) Sentry.captureException(error)
    console.error('Unhandled error:', error)
  }, [error])

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4 py-12">
      <Card className="w-full max-w-md border-border/70 bg-card/95 py-0 shadow-sm">
        <CardHeader className="space-y-4 border-b border-border/65 pb-5 text-center">
          <span className="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-lg border border-destructive/30 bg-destructive/10 text-destructive">
            <AlertCircle className="h-5 w-5" />
          </span>
          <div className="space-y-1.5">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Application error</p>
            <CardTitle className="text-2xl tracking-tight">Something went wrong</CardTitle>
            <p className="text-sm text-muted-foreground">
              An unexpected error occurred. You can retry or go back to the home page.
            </p>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 p-5 sm:flex-row">
          <Button asChild variant="outline" className="w-full">
            <Link href="/">
              <Home className="h-4 w-4" />
              Go home
            </Link>
          </Button>
          <Button className="w-full" onClick={reset}>
            Try again
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
