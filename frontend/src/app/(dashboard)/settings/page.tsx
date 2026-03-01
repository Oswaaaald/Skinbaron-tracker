"use client"

import { useAuth } from "@/contexts/auth-context"
import { ProfileSettings } from "@/components/profile-settings"
import { ProfileSkeleton } from "@/components/ui/skeletons"

export default function SettingsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <ProfileSkeleton />
  }

  return (
    <div className="space-y-4">
      <div className="animate-fade-up">
        <h2 className="text-2xl font-bold tracking-tight">Profile &amp; Settings</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Manage your account and preferences
        </p>
      </div>
      <ProfileSettings />
    </div>
  )
}
