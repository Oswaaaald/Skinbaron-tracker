"use client"

import { useAuth } from "@/contexts/auth-context"
import { ProfileSettings } from "@/components/profile/settings"
import { ProfileSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { Settings } from "lucide-react"

export default function SettingsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <ProfileSkeleton />
  }

  return (
    <div className="space-y-5">
      <PageHeader
        icon={Settings}
        eyebrow="Account"
        title="Profile & Settings"
        description="Manage your profile, security preferences, linked accounts, and activity history."
      />
      <ProfileSettings />
    </div>
  )
}
