"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const ProfileSettings = lazy(() => import("@/components/profile-settings").then(m => ({ default: m.ProfileSettings })))

export default function SettingsPage() {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Profile & Settings</h2>
        <p className="text-muted-foreground">
          Manage your account and preferences
        </p>
      </div>
      <Suspense fallback={<LoadingSpinner />}>
        <ProfileSettings />
      </Suspense>
    </div>
  )
}
