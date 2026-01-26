"use client"

import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { useAuth } from "@/contexts/auth-context"
import { ProfileSettings } from "@/components/profile-settings"

export default function SettingsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
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
