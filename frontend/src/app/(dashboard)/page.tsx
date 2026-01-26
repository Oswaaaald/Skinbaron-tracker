"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { 
  Activity, 
  Bell, 
  Settings,
  ArrowRight,
  Webhook,
} from "lucide-react"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"

export default function DashboardPage() {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getSystemStatus(), 'Failed to load system status'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 5 * 60 * 1000,
    refetchInterval: isVisible ? 5 * 60 * 1000 : false,
    refetchOnWindowFocus: true,
  })

  const { data: userStats } = useQuery({
    queryKey: ['user-stats'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserStats(), 'Failed to load user stats'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 30_000,
    refetchInterval: isVisible ? 30_000 : false,
    refetchOnWindowFocus: true,
  })

  const isSchedulerRunning = systemStatus?.data?.scheduler.isRunning
  const totalRules = userStats?.data?.totalRules || 0
  const enabledRules = userStats?.data?.enabledRules || 0
  const todayAlerts = userStats?.data?.todayAlerts || 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Monitor CS2 skins with custom alerts and Discord notifications
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <Badge variant={isSchedulerRunning ? "default" : "secondary"}>
              {isSchedulerRunning ? "Active" : "Inactive"}
            </Badge>
            <p className="text-xs text-muted-foreground mt-2">
              {isSchedulerRunning ? "Monitoring active" : "Monitoring paused"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Settings className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{enabledRules}/{totalRules}</div>
            <p className="text-xs text-muted-foreground">
              Enabled rules
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Today&apos;s Alerts</CardTitle>
            <Bell className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{todayAlerts}</div>
            <p className="text-xs text-muted-foreground">
              Last 24 hours
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Link href="/rules" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Rules
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                Manage monitoring rules
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/alerts" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Alerts
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                View triggered alerts
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/webhooks" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Webhook className="h-5 w-5" />
                  Webhooks
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                Discord notifications
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>
      </div>

      {totalRules === 0 && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Create your first rule to start monitoring CS2 skins
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/rules">
              <Button>
                <Settings className="mr-2 h-4 w-4" />
                Create Your First Rule
              </Button>
            </Link>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
