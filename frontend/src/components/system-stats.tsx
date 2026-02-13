"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { 
  Activity,
  AlertCircle,
  CheckCircle,
  Clock
} from "lucide-react"
import { apiClient, type ApiResponse, type SystemStats as SystemStatsType } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"
import { LoadingState } from "@/components/ui/loading-state"
import { formatUptime, formatSystemDate } from "@/lib/formatters"
import { QUERY_KEYS, POLL_INTERVAL } from "@/lib/constants"

export function SystemStats({ enabled = true, prefetched }: { enabled?: boolean; prefetched?: ApiResponse<SystemStatsType> | null }) {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

  const STATUS_POLL_MS = 30_000

  const shouldFetch = enabled && isReady && isAuthenticated && isVisible && !prefetched

  const { data: statusResponse, isLoading: isLoadingStatus } = useQuery({
    queryKey: [QUERY_KEYS.SYSTEM_STATUS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getSystemStatus(), 'Failed to load system status'),
    enabled: shouldFetch,
    staleTime: STATUS_POLL_MS,
    refetchInterval: shouldFetch ? STATUS_POLL_MS : false,
    refetchOnWindowFocus: enabled,
  })

  // Alerts statistics - used for real-time updates
  useQuery({
    queryKey: [QUERY_KEYS.ALERT_STATS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getAlertStats(), 'Failed to load alert stats'),
    enabled: enabled && isReady && isAuthenticated && isVisible,
    staleTime: POLL_INTERVAL,
    refetchInterval: enabled && isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: enabled,
    notifyOnChangeProps: ['data', 'error'],
  })


  if (shouldFetch && isLoadingStatus) {
    return <LoadingState variant="card" />
  }

  const status = prefetched?.data || statusResponse?.data
  const health = status?.health

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
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Status</span>
            <Badge variant={health?.status === 'healthy' ? 'default' : 'destructive'}>
              {health?.status === 'healthy' ? (
                <CheckCircle className="h-3 w-3 mr-1" />
              ) : (
                <AlertCircle className="h-3 w-3 mr-1" />
              )}
              {health?.status || 'unknown'}
            </Badge>
          </div>
          
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Uptime</span>
            <span className="text-sm">{formatUptime(health?.stats?.uptime)}</span>
          </div>
          
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Version</span>
            <span className="text-sm font-mono">{health?.stats?.version || 'N/A'}</span>
          </div>

          <Separator />
          
          <div>
            <h3 className="text-sm font-medium mb-2">Services Status</h3>
            <div className="space-y-2">
              {health?.services && Object.entries(health.services).map(([service, serviceStatus]) => (
                <div key={service} className="flex items-center justify-between">
                  <span className="text-sm capitalize">{service === 'scheduler' ? 'Alert Monitoring' : service}</span>
                  <Badge variant={serviceStatus === 'healthy' || serviceStatus === 'running' ? 'default' : 'destructive'} className="text-xs">
                    {serviceStatus === 'healthy' || serviceStatus === 'running' ? 'Online' : 'Offline'}
                  </Badge>
                </div>
              ))}
              {!health?.services && (
                <div className="text-center text-sm text-muted-foreground">
                  Loading services...
                </div>
              )}
            </div>
          </div>
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
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Status</span>
            <Badge variant={status?.['scheduler']?.isRunning || health?.['services']?.['scheduler'] === 'running' ? 'default' : 'secondary'}>
              {status?.['scheduler']?.isRunning || health?.['services']?.['scheduler'] === 'running' ? (
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
            <span className="text-sm">{status?.['scheduler']?.totalRuns ?? 0}</span>
          </div>
          
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Alerts Sent</span>
            <span className="text-sm">{status?.['scheduler']?.totalAlerts ?? 0}</span>
          </div>
          
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Last Scan</span>
              <span className="text-xs text-muted-foreground">
                {formatSystemDate(status?.['scheduler']?.lastRunTime)}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Next Scan</span>
              <span className="text-xs text-muted-foreground">
                {formatSystemDate(status?.['scheduler']?.nextRunTime)}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>


    </div>
  )
}