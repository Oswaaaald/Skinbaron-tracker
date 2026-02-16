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
    <div className="min-h-[calc(100vh-56px)]">
      {/* Top bar */}
      <header className="sticky top-0 z-40 border-b border-border/40 bg-background/80 backdrop-blur-lg supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 sm:px-6">
          <div className="flex h-14 items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <h1 className="text-base sm:text-lg font-semibold tracking-tight whitespace-nowrap">SkinBaron Tracker</h1>
              <DashboardNav />
            </div>
            <div className="flex items-center gap-1.5 sm:gap-2">
              <ThemeToggle />
              <UserNav />
              <MobileNavTrigger />
            </div>
          </div>
        </div>
      </header>
      
      {/* Page content */}
      <div className="container mx-auto px-4 sm:px-6 py-4 sm:py-6">
        {children}
      </div>
    </div>
  )
}
