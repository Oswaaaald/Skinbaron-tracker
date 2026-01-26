"use client"

import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { useAuth } from "@/contexts/auth-context"
import { SystemStats } from "@/components/system-stats"

export default function AdminSystemPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Status</h2>
        <p className="text-muted-foreground">
          Monitor system health and performance
        </p>
      </div>
      <SystemStats enabled={true} />
    </div>
  )
}
