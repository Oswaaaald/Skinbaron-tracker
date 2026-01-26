"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const SystemStats = lazy(() => import("@/components/system-stats").then(m => ({ default: m.SystemStats })))

export default function AdminSystemPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Status</h2>
        <p className="text-muted-foreground">
          Monitor system health and performance
        </p>
      </div>
      <Suspense fallback={<LoadingSpinner />}>
        <SystemStats enabled={true} />
      </Suspense>
    </div>
  )
}
