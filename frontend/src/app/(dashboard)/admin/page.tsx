"use client"

import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { useAuth } from "@/contexts/auth-context"
import { AdminPanel } from "@/components/admin-panel"

export default function AdminPage() {
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
        <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
        <p className="text-muted-foreground">
          Manage users and system settings
        </p>
      </div>
      <AdminPanel />
    </div>
  )
}
