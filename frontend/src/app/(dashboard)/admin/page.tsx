"use client"

import { useAuth } from "@/contexts/auth-context"
import { AdminPanel } from "@/components/admin-panel"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function AdminPage() {
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
        <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
        <p className="text-muted-foreground">
          Manage users and system settings
        </p>
      </div>
      <AdminPanel />
    </div>
  )
}
