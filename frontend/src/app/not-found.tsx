import Link from 'next/link';
import { Button } from '@/components/ui/button';

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="text-center space-y-6">
        <p className="text-8xl font-bold tracking-tighter text-primary/20 select-none">404</p>
        <div className="space-y-2">
          <h2 className="text-xl font-semibold tracking-tight">Page Not Found</h2>
          <p className="text-sm text-muted-foreground max-w-xs mx-auto">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
          </p>
        </div>
        <Button asChild size="sm">
          <Link href="/">Go Home</Link>
        </Button>
      </div>
    </div>
  )
}
