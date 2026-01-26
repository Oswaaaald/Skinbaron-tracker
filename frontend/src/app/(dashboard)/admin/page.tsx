"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const AdminPanel = lazy(() => import("@/components/admin-panel").then(m => ({ default: m.AdminPanel })))

export default function AdminPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
        <p className="text-muted-foreground">
          Manage users and system settings
        </p>
      </div>
      <Suspense fallback={<LoadingSpinner />}>
        <AdminPanel />
      </Suspense>
    </div>
  )
}
