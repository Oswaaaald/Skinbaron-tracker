"use client"

import { AlertsGrid } from "@/components/alerts-grid"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"

export default function AlertsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Alert History</h2>
        <p className="text-muted-foreground">
          View all triggered alerts with detailed information
        </p>
      </div>
      <AlertsGrid />
    </div>
  )
}
