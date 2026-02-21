"use client"

import { AlertsGrid } from "@/components/alerts-grid"
import { useAuth } from "@/contexts/auth-context"
import { AlertsGridSkeleton } from "@/components/ui/skeletons"

export default function AlertsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <AlertsGridSkeleton />
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
