"use client"

import { useAuth } from "@/contexts/auth-context"
import { ProfileSettings } from "@/components/profile-settings"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function SettingsPage() {
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
