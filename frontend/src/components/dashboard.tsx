"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { 
  Activity, 
  AlertTriangle, 
  Bell, 
  Play, 
  Pause, 
  RotateCcw, 
  Settings, 
  Moon, 
  Sun 
} from "lucide-react"
import { useTheme } from "next-themes"
import { toast } from "sonner"

import { RulesTable } from "@/components/rules-table"
import { AlertsTable } from "@/components/alerts-table"
import { RuleDialog } from "@/components/rule-dialog"
import { SystemStats } from "@/components/system-stats"
import { UserNav } from "@/components/user-nav"
import { apiClient } from "@/lib/api"

export function Dashboard() {
  const { theme, setTheme } = useTheme()
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false)

  // Fetch system status
  const { data: systemStatus, isLoading: isLoadingStatus, refetch: refetchStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => apiClient.getSystemStatus(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Fetch health status
  const { data: health, isLoading: isLoadingHealth } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient.getHealth(),
    refetchInterval: 60000, // Refresh every minute
  })

  const handleSchedulerAction = async (action: 'start' | 'stop' | 'run') => {
    try {
      let response;
      switch (action) {
        case 'start':
          response = await apiClient.startScheduler()
          break
        case 'stop':
          response = await apiClient.stopScheduler()
          break
        case 'run':
          response = await apiClient.runScheduler()
          break
      }
      
      if (response.success) {
        toast.success(response.data?.message || `Scheduler ${action} successful`)
        refetchStatus()
      } else {
        toast.error(response.error || `Failed to ${action} scheduler`)
      }
    } catch (error) {
      toast.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const isSchedulerRunning = systemStatus?.data?.scheduler.isRunning
  const totalRules = systemStatus?.data?.database.totalRules || 0
  const enabledRules = systemStatus?.data?.database.enabledRules || 0
  const totalAlerts = systemStatus?.data?.database.totalAlerts || 0
  const todayAlerts = systemStatus?.data?.database.todayAlerts || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SkinBaron Alerts</h1>
          <p className="text-muted-foreground">
            Monitor CS2 skins with custom alerts and Discord notifications
          </p>
        </div>
        <div className="flex items-center gap-4">
          <UserNav />
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
            <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
            <span className="sr-only">Toggle theme</span>
          </Button>
          <Button
            variant="outline"
            onClick={() => refetchStatus()}
            disabled={isLoadingStatus}
          >
            <RotateCcw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Scheduler Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge variant={isSchedulerRunning ? "default" : "secondary"}>
                {isSchedulerRunning ? "Running" : "Stopped"}
              </Badge>
              <div className="flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleSchedulerAction(isSchedulerRunning ? 'stop' : 'start')}
                  disabled={isLoadingStatus}
                >
                  {isSchedulerRunning ? (
                    <Pause className="h-3 w-3" />
                  ) : (
                    <Play className="h-3 w-3" />
                  )}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleSchedulerAction('run')}
                  disabled={isLoadingStatus || !isSchedulerRunning}
                >
                  <RotateCcw className="h-3 w-3" />
                </Button>
              </div>
            </div>
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
      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
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

        <TabsContent value="alerts" className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Alert History</h2>
            <p className="text-muted-foreground">
              View all triggered alerts and notifications
            </p>
          </div>
          <AlertsTable />
        </TabsContent>

        <TabsContent value="system" className="space-y-4">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">System Status</h2>
            <p className="text-muted-foreground">
              Monitor system health and performance
            </p>
          </div>
          <SystemStats />
        </TabsContent>
      </Tabs>

      {/* Rule Creation Dialog */}
      <RuleDialog
        open={isRuleDialogOpen}
        onOpenChange={setIsRuleDialogOpen}
      />
    </div>
  )
}