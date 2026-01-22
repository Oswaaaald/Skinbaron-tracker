"use client"

import { useState, useEffect, useRef, lazy, Suspense } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { 
  Activity, 
  AlertTriangle, 
  Bell, 
  Settings, 
  Moon, 
  Sun,
  Monitor
} from "lucide-react"
import { useTheme } from "next-themes"

import { RulesTable } from "@/components/rules-table"
import { AlertsGrid } from "@/components/alerts-grid"
import { RuleDialog } from "@/components/rule-dialog"
import { UserNav } from "@/components/user-nav"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"

// Lazy load heavy components
const SystemStats = lazy(() => import("@/components/system-stats").then(m => ({ default: m.SystemStats })))
const WebhooksTable = lazy(() => import("@/components/webhooks-table").then(m => ({ default: m.WebhooksTable })))
const AdminPanel = lazy(() => import("@/components/admin-panel").then(m => ({ default: m.AdminPanel })))
const ProfileSettings = lazy(() => import("@/components/profile-settings").then(m => ({ default: m.ProfileSettings })))

export function Dashboard() {
  const { theme, setTheme } = useTheme()
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false)
  const { isReady, isAuthenticated, user } = useAuth()
  const isVisible = usePageVisible()
  const queryClient = useQueryClient()
  
  // Restore active tab from localStorage on mount
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('dashboard-active-tab') || 'rules'
    }
    return 'rules'
  })
  // Reset tab to 'rules' if user loses admin access while on admin/system tab
  useEffect(() => {
    if (!user?.is_admin && (activeTab === 'admin' || activeTab === 'system')) {
      setActiveTab('rules')
    }
  }, [user?.is_admin, activeTab])

  // Save active tab to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('dashboard-active-tab', activeTab)
  }, [activeTab])

  // Fetch system status
  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getSystemStatus(), 'Failed to load system status'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 5 * 60 * 1000,
    refetchInterval: isVisible ? 5 * 60 * 1000 : false,
    refetchOnWindowFocus: true,
  })

  // Fetch user statistics
  const { data: userStats, isLoading: _isLoadingUserStats } = useQuery({
    queryKey: ['user-stats'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserStats(), 'Failed to load user stats'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 30_000,
    refetchInterval: isVisible ? 30_000 : false,
    refetchOnWindowFocus: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  // Track previous alert counts to detect changes and invalidate alerts query
  const prevTotalAlertsRef = useRef<number | null>(null)
  const prevTodayAlertsRef = useRef<number | null>(null)
  
  useEffect(() => {
    const currentTotal = userStats?.data?.totalAlerts ?? 0
    const currentToday = userStats?.data?.todayAlerts ?? 0
    
    // If alert counts changed (and it's not the first load), invalidate alerts query
    if (prevTotalAlertsRef.current !== null && 
        (prevTotalAlertsRef.current !== currentTotal || prevTodayAlertsRef.current !== currentToday)) {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    }
    
    prevTotalAlertsRef.current = currentTotal
    prevTodayAlertsRef.current = currentToday
  }, [userStats?.data?.totalAlerts, userStats?.data?.todayAlerts, queryClient])




  const isSchedulerRunning = systemStatus?.data?.scheduler.isRunning
  // Use user stats instead of global stats
  const totalRules = userStats?.data?.totalRules || 0
  const enabledRules = userStats?.data?.enabledRules || 0
  const totalAlerts = userStats?.data?.totalAlerts || 0
  const todayAlerts = userStats?.data?.todayAlerts || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SkinBaron Tracker</h1>
          <p className="text-muted-foreground">
            Monitor CS2 skins with custom alerts and Discord notifications
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Button
            variant="outline"
            size="icon"
            onClick={() => {
              // Cycle through: light → dark → system
              if (theme === "light") setTheme("dark")
              else if (theme === "dark") setTheme("system")
              else setTheme("light")
            }}
            title={theme === "system" ? "Theme: Auto" : theme === "dark" ? "Theme: Dark" : "Theme: Light"}
          >
            {/* Light theme icon */}
            {theme === "light" && (
              <Sun className="h-[1.2rem] w-[1.2rem] transition-all" />
            )}
            
            {/* Dark theme icon */}
            {theme === "dark" && (
              <Moon className="h-[1.2rem] w-[1.2rem] transition-all" />
            )}
            
            {/* System/Auto theme icon */}
            {theme === "system" && (
              <Monitor className="h-[1.2rem] w-[1.2rem] transition-all" />
            )}
            
            <span className="sr-only">Toggle theme</span>
          </Button>
          <UserNav onTabChange={setActiveTab} />
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Monitoring Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge variant={isSchedulerRunning ? "default" : "secondary"}>
                {isSchedulerRunning ? "Active" : "Inactive"}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              {isSchedulerRunning ? "Monitoring your rules automatically" : "System monitoring paused"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
            <Settings className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalRules}</div>
            <p className="text-xs text-muted-foreground">
              {enabledRules} enabled
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
            <Bell className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalAlerts}</div>
            <p className="text-xs text-muted-foreground">
              All time
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Today&apos;s Alerts</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{todayAlerts}</div>
            <p className="text-xs text-muted-foreground">
              Last 24 hours
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          {user?.is_admin && <TabsTrigger value="admin">Admin</TabsTrigger>}
          {user?.is_admin && <TabsTrigger value="system">System</TabsTrigger>}
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-2xl font-bold tracking-tight">Alert Rules</h2>
              <p className="text-muted-foreground">
                Manage your custom skin monitoring rules
              </p>
            </div>
            <Button onClick={() => setIsRuleDialogOpen(true)}>
              Create Rule
            </Button>
          </div>
          <RulesTable />
        </TabsContent>

        <TabsContent value="webhooks" className="space-y-4">
          <Suspense fallback={<LoadingSpinner />}>
            <WebhooksTable />
          </Suspense>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Alert History</h2>
            <p className="text-muted-foreground">
              View all triggered alerts with detailed information
            </p>
          </div>
          <AlertsGrid />
        </TabsContent>
        <TabsContent value="settings" className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Profile & Settings</h2>
            <p className="text-muted-foreground">
              Manage your account and preferences
            </p>
          </div>
          <Suspense fallback={<LoadingSpinner />}>
            <ProfileSettings />
          </Suspense>
        </TabsContent>
        {user?.is_admin && (
          <TabsContent value="admin" className="space-y-4">
            <div>
              <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
              <p className="text-muted-foreground">
                Manage users and system settings
              </p>
            </div>
            <Suspense fallback={<LoadingSpinner />}>
              <AdminPanel />
            </Suspense>
          </TabsContent>
        )}

        {user?.is_admin && (
          <TabsContent value="system" className="space-y-4">
            <div>
              <h2 className="text-2xl font-bold tracking-tight">System Status</h2>
              <p className="text-muted-foreground">
                Monitor system health and performance
              </p>
            </div>
            <Suspense fallback={<LoadingSpinner />}>
              <SystemStats enabled={activeTab === 'system'} />
            </Suspense>
          </TabsContent>
        )}
      </Tabs>

      {/* Rule Creation Dialog */}
      <RuleDialog
        open={isRuleDialogOpen}
        onOpenChange={setIsRuleDialogOpen}
      />
    </div>
  )
}