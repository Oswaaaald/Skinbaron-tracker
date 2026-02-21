"use client"

import { useAuth } from "@/contexts/auth-context"
import { AdminPanel } from "@/components/admin-panel"
import { AdminPanelSkeleton } from "@/components/ui/skeletons"

export default function AdminPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <AdminPanelSkeleton />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Manage users and system settings
        </p>
      </div>
      <AdminPanel />
    </div>
  )
}
