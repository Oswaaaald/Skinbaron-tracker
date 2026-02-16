"use client"

import { useAuth } from "@/contexts/auth-context"
import { SystemStats } from "@/components/system-stats"
import { LoadingState } from "@/components/ui/loading-state"

export default function AdminSystemPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Status</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Monitor system health and performance
        </p>
      </div>
      <SystemStats enabled={true} />
    </div>
  )
}
