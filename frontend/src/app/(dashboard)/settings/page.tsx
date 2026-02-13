"use client"

import { useAuth } from "@/contexts/auth-context"
import { ProfileSettings } from "@/components/profile-settings"
import { LoadingState } from "@/components/ui/loading-state"

export default function SettingsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Profile & Settings</h2>
        <p className="text-muted-foreground">
          Manage your account and preferences
        </p>
      </div>
      <ProfileSettings />
    </div>
  )
}
