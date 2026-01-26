"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { 
  Activity, 
  AlertTriangle, 
  Bell, 
  Settings,
  ArrowRight,
  Webhook,
  TrendingUp,
  Clock
} from "lucide-react"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"

export default function DashboardPage() {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

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
  const { data: userStats } = useQuery({
    queryKey: ['user-stats'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserStats(), 'Failed to load user stats'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 30_000,
    refetchInterval: isVisible ? 30_000 : false,
    refetchOnWindowFocus: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  const isSchedulerRunning = systemStatus?.data?.scheduler.isRunning
  const totalRules = userStats?.data?.totalRules || 0
  const enabledRules = userStats?.data?.enabledRules || 0
  const totalAlerts = userStats?.data?.totalAlerts || 0
  const todayAlerts = userStats?.data?.todayAlerts || 0

  // Fetch webhooks count
  const { data: webhooks } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getWebhooks(false), 'Failed to load webhooks'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 60_000,
    refetchInterval: isVisible ? 60_000 : false,
    refetchOnWindowFocus: true,
  })

  const totalWebhooks = webhooks?.data?.length || 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Monitor CS2 skins with custom alerts and Discord notifications
        </p>
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

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="hover:border-primary transition-colors cursor-pointer group">
          <Link href="/rules">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Rules
                </span>
                <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
              </CardTitle>
              <CardDescription>
                Manage your monitoring rules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <TrendingUp className="h-4 w-4" />
                {enabledRules} active rules monitoring the market
              </div>
            </CardContent>
          </Link>
        </Card>

        <Card className="hover:border-primary transition-colors cursor-pointer group">
          <Link href="/alerts">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Recent Alerts
                </span>
                <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
              </CardTitle>
              <CardDescription>
                View triggered alerts
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                {todayAlerts} alerts in the last 24 hours
              </div>
            </CardContent>
          </Link>
        </Card>

        <Card className="hover:border-primary transition-colors cursor-pointer group">
          <Link href="/webhooks">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Webhook className="h-5 w-5" />
                  Webhooks
                </span>
                <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
              </CardTitle>
              <CardDescription>
                Configure Discord notifications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Webhook className="h-4 w-4" />
                {totalWebhooks} webhook{totalWebhooks !== 1 ? 's' : ''} configured
              </div>
            </CardContent>
          </Link>
        </Card>
      </div>

      {/* Getting Started */}
      {totalRules === 0 && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Create your first rule to start monitoring CS2 skins
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Set up custom rules to monitor specific skins, price ranges, and wear conditions. 
                Get instant Discord notifications when items matching your criteria are listed.
              </p>
              <Link href="/rules">
                <Button>
                  <Settings className="mr-2 h-4 w-4" />
                  Create Your First Rule
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
