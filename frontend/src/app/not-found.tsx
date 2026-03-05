import Link from 'next/link'
import { Compass, Home } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4 py-12">
      <Card className="w-full max-w-md border-border/70 bg-card/95 py-0 shadow-sm">
        <CardHeader className="space-y-4 border-b border-border/65 pb-5 text-center">
          <span className="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-lg border border-border/70 bg-background/80 text-muted-foreground">
            <Compass className="h-5 w-5" />
          </span>
          <div className="space-y-1.5">
            <p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Error 404</p>
            <CardTitle className="text-2xl tracking-tight">Page not found</CardTitle>
            <p className="text-sm text-muted-foreground">
              The requested page does not exist or has been moved.
            </p>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 p-5 sm:flex-row">
          <Button asChild className="w-full">
            <Link href="/">
              <Home className="h-4 w-4" />
              Go home
            </Link>
          </Button>
          <Button asChild variant="outline" className="w-full">
            <Link href="/alerts">Open dashboard</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
