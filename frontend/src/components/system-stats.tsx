"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { 
  Activity,
  AlertCircle,
  CheckCircle,
  Clock
} from "lucide-react"
import { toast } from "sonner"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"

export function SystemStats() {
  const { isLoading: isAuthLoading, token } = useAuth()

  const { data: healthResponse, isLoading: isLoadingHealth } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient.getHealth(),
    refetchInterval: 30000, // 30 seconds
    enabled: !isAuthLoading && !!token, // Wait for auth loading to finish and token to be present
  })

  const { data: statusResponse, isLoading: isLoadingStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => apiClient.getSystemStatus(),
    refetchInterval: 5 * 60 * 1000, // 5 minutes
    enabled: !isAuthLoading && !!token, // Wait for auth loading to finish and token to be present
  })

  // Alerts statistics - used for real-time updates
  const { data: alertStatsResponse } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => apiClient.getAlertStats(),
    refetchInterval: 10000, // 10 seconds for real-time stats
    refetchIntervalInBackground: true, // Keep refreshing in background
    enabled: !isAuthLoading && !!token, // Wait for auth loading to finish and token to be present
  })



  if (isLoadingHealth || isLoadingStatus) {
    return <LoadingSpinner />
  }

  const healthData = healthResponse?.success ? (healthResponse as any) : null
  const health = healthData ? {
    status: healthData.status,
    services: healthData.services,
    stats: healthData.stats,
    timestamp: healthData.timestamp
  } : null
  const status = statusResponse?.data
  const alertStats = alertStatsResponse?.data

  const formatUptime = (uptimeSeconds?: number) => {
    if (!uptimeSeconds) return 'N/A'
    const hours = Math.floor(uptimeSeconds / 3600)
    const minutes = Math.floor((uptimeSeconds % 3600) / 60)
    return `${hours}h ${minutes}m`
  }

  const formatMemory = (bytes?: number) => {
    if (!bytes) return 'N/A'
    return `${Math.round(bytes / 1024 / 1024)}MB`
  }

  const formatDate = (dateString?: Date | string | null) => {
    if (!dateString) return 'Never'
    return new Date(dateString).toLocaleString()
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* System Health */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            System Health
          </CardTitle>
          <CardDescription>
            Overall system status and availability
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {health ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status</span>
                <Badge variant={health.status === 'healthy' ? 'default' : 'destructive'}>
                  {health.status === 'healthy' ? (
                    <CheckCircle className="h-3 w-3 mr-1" />
                  ) : (
                    <AlertCircle className="h-3 w-3 mr-1" />
                  )}
                  {health.status}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Uptime</span>
                <span className="text-sm">{formatUptime(health.stats?.uptime)}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Version</span>
                <span className="text-sm font-mono">{health.stats?.version || 'N/A'}</span>
              </div>

              <Separator />
              
              <div>
                <h4 className="text-sm font-medium mb-2">Services Status</h4>
                <div className="space-y-2">
                  {health.services && Object.entries(health.services).map(([service, serviceStatus]) => (
                    <div key={service} className="flex items-center justify-between">
                      <span className="text-sm capitalize">{service === 'scheduler' ? 'Alert Monitoring' : service}</span>
                      <Badge variant={serviceStatus === 'healthy' || serviceStatus === 'running' ? 'default' : 'destructive'} className="text-xs">
                        {serviceStatus === 'healthy' || serviceStatus === 'running' ? 'Online' : 'Offline'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground">
              Unable to load health information
            </div>
          )}
        </CardContent>
      </Card>

      {/* Alert Monitoring Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Alert Monitoring
          </CardTitle>
          <CardDescription>
            Automatic scanning for new items matching your rules
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status?.scheduler && Object.keys(status.scheduler).length > 0 ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status</span>
                <Badge variant={status.scheduler.isRunning ? 'default' : 'secondary'}>
                  {status.scheduler.isRunning ? (
                    <>
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Active
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-3 w-3 mr-1" />
                      Inactive
                    </>
                  )}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Scans Completed</span>
                <span className="text-sm">{status.scheduler.totalRuns || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Alerts Sent</span>
                <span className="text-sm">{status.scheduler.totalAlerts || 0}</span>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Last Scan</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(status.scheduler.lastRunTime)}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Next Scan</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(status.scheduler.nextRunTime)}
                  </span>
                </div>
              </div>

            </>
          ) : health?.services?.scheduler ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status</span>
                <Badge variant={health.services.scheduler === 'running' ? 'default' : 'secondary'}>
                  {health.services.scheduler === 'running' ? 'Active' : 'Inactive'}
                </Badge>
              </div>
              <div className="text-center text-sm text-muted-foreground mt-4">
                System is monitoring your rules automatically
                <br />
                <span className="text-xs">Scans happen every few minutes</span>
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground">
              Unable to load monitoring information
            </div>
          )}
        </CardContent>
      </Card>


    </div>
  )
}