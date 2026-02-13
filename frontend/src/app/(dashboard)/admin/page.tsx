"use client"

import { useAuth } from "@/contexts/auth-context"
import { AdminPanel } from "@/components/admin-panel"
import { LoadingState } from "@/components/ui/loading-state"

export default function AdminPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
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
