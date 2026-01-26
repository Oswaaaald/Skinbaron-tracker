"use client"

import { useAuth } from "@/contexts/auth-context"
import { SystemStats } from "@/components/system-stats"

export default function AdminSystemPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
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
