'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'

export default function NotFound() {
  const router = useRouter()

  return (
    <div className="mx-auto w-full max-w-7xl px-4 py-10 sm:px-6 sm:py-12">
      <div className="flex min-h-[62vh] items-center justify-center">
        <div className="w-full max-w-xl rounded-2xl border border-border/70 bg-card/95 p-7 text-center shadow-sm sm:p-10">
          <p className="text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground">Error 404</p>
          <p className="mt-3 text-6xl font-semibold tracking-[-0.04em] text-foreground/85 sm:text-7xl">Not Found</p>
          <p className="mx-auto mt-4 max-w-md text-sm leading-relaxed text-muted-foreground sm:text-base">
            The page you requested does not exist, was moved, or is currently unavailable.
          </p>
          <div className="mt-7 flex flex-col gap-3 sm:flex-row sm:justify-center">
            <Button className="w-full sm:w-auto" variant="outline" onClick={() => router.back()}>
              Go back
            </Button>
            <Button asChild className="w-full sm:w-auto">
              <Link href="/alerts">Open dashboard</Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
