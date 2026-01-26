"use client"

import { AlertsGrid } from "@/components/alerts-grid"
import { useAuth } from "@/contexts/auth-context"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function AlertsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
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
