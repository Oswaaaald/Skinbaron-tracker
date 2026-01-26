'use client'

import { DashboardNav, MobileNavTrigger } from "@/components/dashboard-nav"
import { UserNav } from "@/components/user-nav"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"
import { useEffect, useState } from "react"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { isAuthenticated, isLoading, isReady } = useAuth()
  const [hasBeenAuthenticated, setHasBeenAuthenticated] = useState(false)

  // Track if user has been authenticated at least once
  useEffect(() => {
    if (isAuthenticated) {
      setHasBeenAuthenticated(true)
    }
  }, [isAuthenticated])

  // Show navigation if:
  // 1. User is currently authenticated, OR
  // 2. User was authenticated before (during page transitions/reloads)
  const shouldShowNav = isAuthenticated || (hasBeenAuthenticated && isLoading)

  // For initial load, wait for auth check before deciding layout
  if (!isReady && !hasBeenAuthenticated) {
    return children
  }

  // If user is not authenticated and has never been, show children without nav
  if (!shouldShowNav) {
    return children
  }

  return (
    <div className="container mx-auto p-3 sm:p-4">
      <div className="flex items-center justify-between mb-4 sm:mb-6 gap-2 sm:gap-4">
        <h1 className="text-xl sm:text-2xl md:text-3xl font-bold">SkinBaron Tracker</h1>
        <div className="flex items-center gap-1.5 sm:gap-2 md:gap-4">
          <ThemeToggle />
          <UserNav />
          <MobileNavTrigger />
        </div>
      </div>
      
      <div className="mb-4 sm:mb-6">
        <DashboardNav />
      </div>
      
      {children}
    </div>
  )
}
