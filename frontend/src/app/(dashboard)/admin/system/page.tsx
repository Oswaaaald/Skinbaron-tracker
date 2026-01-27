"use client"

import { useAuth } from "@/contexts/auth-context"
import { SystemStats } from "@/components/system-stats"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function AdminSystemPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
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
