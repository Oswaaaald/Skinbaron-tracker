"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { 
  Activity,
  AlertCircle,
  CheckCircle,
  Clock,
  Database,
  Server,
  Settings,
  Trash2,
  RotateCcw
} from "lucide-react"
import { toast } from "sonner"
import { apiClient } from "@/lib/api"

export function SystemStats() {
  const queryClient = useQueryClient()

  const { data: healthResponse, isLoading: isLoadingHealth } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient.getHealth(),
    refetchInterval: 30000,
  })

  const { data: statusResponse, isLoading: isLoadingStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => apiClient.getSystemStatus(),
    refetchInterval: 30000,
  })

  const { data: alertStatsResponse } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => apiClient.getAlertStats(),
    refetchInterval: 60000,
  })

  const cleanupAlertsMutation = useMutation({
    mutationFn: () => apiClient.cleanupAlerts(),
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Cleanup completed: ${data.data?.deletedCount || 0} alerts deleted`)
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
        queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
        queryClient.invalidateQueries({ queryKey: ['system-status'] })
      } else {
        toast.error(data.error || 'Cleanup failed')
      }
    },
    onError: (error) => {
      toast.error(`Cleanup failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
  })

  const handleCleanupAlerts = () => {
    if (confirm('Are you sure you want to clean up old alerts? This will remove alerts older than the configured retention period.')) {
      cleanupAlertsMutation.mutate()
    }
  }

  if (isLoadingHealth || isLoadingStatus) {
    return <LoadingSpinner />
  }

  const health = healthResponse?.data
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
      {/* Health Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            System Health
          </CardTitle>
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
                <span className="text-sm font-medium">Memory Usage</span>
                <span className="text-sm font-mono">
                  {formatMemory(health.stats?.memory?.heapUsed)} / {formatMemory(health.stats?.memory?.heapTotal)}
                </span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Version</span>
                <span className="text-sm font-mono">{health.stats?.version || 'N/A'}</span>
              </div>

              <Separator />
              
              <div>
                <h4 className="text-sm font-medium mb-2">Services</h4>
                <div className="space-y-2">
                  {health.services && Object.entries(health.services).map(([service, status]) => (
                    <div key={service} className="flex items-center justify-between">
                      <span className="text-sm capitalize">{service}</span>
                      <Badge variant={status === 'healthy' ? 'default' : 'destructive'} className="text-xs">
                        {status}
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

      {/* Scheduler Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Scheduler Status
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {status?.scheduler && Object.keys(status.scheduler).length > 0 ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status</span>
                <Badge variant={status.scheduler.isRunning ? 'default' : 'secondary'}>
                  {status.scheduler.isRunning ? 'Running' : 'Stopped'}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Total Runs</span>
                <span className="text-sm">{status.scheduler.totalRuns || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Total Alerts</span>
                <span className="text-sm">{status.scheduler.totalAlerts || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Error Count</span>
                <Badge variant={(status.scheduler.errorCount || 0) > 0 ? 'destructive' : 'default'}>
                  {status.scheduler.errorCount || 0}
                </Badge>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Last Run</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(status.scheduler.lastRunTime)}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Next Run</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(status.scheduler.nextRunTime)}
                  </span>
                </div>
              </div>
              
              {status.scheduler.lastError && (
                <>
                  <Separator />
                  <div>
                    <h4 className="text-sm font-medium text-red-600 mb-1">Last Error</h4>
                    <p className="text-xs text-muted-foreground break-all">
                      {status.scheduler.lastError}
                    </p>
                  </div>
                </>
              )}
            </>
          ) : health?.services?.scheduler ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Status</span>
                <Badge variant={health.services.scheduler === 'running' ? 'default' : 'secondary'}>
                  {health.services.scheduler === 'running' ? 'Running' : 'Stopped'}
                </Badge>
              </div>
              <div className="text-center text-sm text-muted-foreground mt-4">
                Detailed scheduler information unavailable
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground">
              Unable to load scheduler information
            </div>
          )}
        </CardContent>
      </Card>

      {/* Database Statistics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Database Statistics
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {status?.database && Object.keys(status.database).length > 0 ? (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{status.database.totalRules || 0}</div>
                  <div className="text-xs text-muted-foreground">Total Rules</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{status.database.enabledRules || 0}</div>
                  <div className="text-xs text-muted-foreground">Enabled Rules</div>
                </div>
              </div>
              
              <Separator />
              
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{status.database.totalAlerts || 0}</div>
                  <div className="text-xs text-muted-foreground">Total Alerts</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{status.database.todayAlerts || 0}</div>
                  <div className="text-xs text-muted-foreground">Today&apos;s Alerts</div>
                </div>
              </div>

              {alertStats && (
                <>
                  <Separator />
                  <div>
                    <h4 className="text-sm font-medium mb-2">Alert Types</h4>
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div className="text-center">
                        <div className="font-mono">{alertStats.alertsByType?.match || 0}</div>
                        <div className="text-muted-foreground">Matches</div>
                      </div>
                      <div className="text-center">
                        <div className="font-mono">{alertStats.alertsByType?.best_deal || 0}</div>
                        <div className="text-muted-foreground">Best Deals</div>
                      </div>
                      <div className="text-center">
                        <div className="font-mono">{alertStats.alertsByType?.new_item || 0}</div>
                        <div className="text-muted-foreground">New Items</div>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </>
          ) : alertStats ? (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{alertStats.totalRules || 0}</div>
                  <div className="text-xs text-muted-foreground">Total Rules</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{alertStats.enabledRules || 0}</div>
                  <div className="text-xs text-muted-foreground">Enabled Rules</div>
                </div>
              </div>
              
              <Separator />
              
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold">{alertStats.totalAlerts || 0}</div>
                  <div className="text-xs text-muted-foreground">Total Alerts</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">{alertStats.todayAlerts || 0}</div>
                  <div className="text-xs text-muted-foreground">Today&apos;s Alerts</div>
                </div>
              </div>
              
              <Separator />
              <div>
                <h4 className="text-sm font-medium mb-2">Alert Types</h4>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="text-center">
                    <div className="font-mono">{alertStats.alertsByType?.match || 0}</div>
                    <div className="text-muted-foreground">Matches</div>
                  </div>
                  <div className="text-center">
                    <div className="font-mono">{alertStats.alertsByType?.best_deal || 0}</div>
                    <div className="text-muted-foreground">Best Deals</div>
                  </div>
                  <div className="text-center">
                    <div className="font-mono">{alertStats.alertsByType?.new_item || 0}</div>
                    <div className="text-muted-foreground">New Items</div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground">
              Unable to load database information
            </div>
          )}
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {status?.config && Object.keys(status.config).length > 0 ? (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Environment</span>
                <Badge variant={status.config.nodeEnv === 'production' ? 'default' : 'secondary'}>
                  {status.config.nodeEnv || 'unknown'}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Poll Schedule</span>
                <span className="text-sm font-mono">{status.config.pollCron || 'N/A'}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Best Deals Feed</span>
                <Badge variant={status.config.enableBestDeals ? 'default' : 'secondary'}>
                  {status.config.enableBestDeals ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Newest Items Feed</span>
                <Badge variant={status.config.enableNewestItems ? 'default' : 'secondary'}>
                  {status.config.enableNewestItems ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Max Feed Price</span>
                <span className="text-sm">${status.config.feedsMaxPrice || 'N/A'}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Max Feed Wear</span>
                <span className="text-sm">{status.config.feedsMaxWear || 'N/A'}</span>
              </div>
            </>
          ) : (
            <div className="text-center text-muted-foreground">
              Configuration information temporarily unavailable
              <br />
              <span className="text-xs">System is running normally</span>
            </div>
          )}
          
          <Separator />
          
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                queryClient.invalidateQueries({ queryKey: ['health'] })
                queryClient.invalidateQueries({ queryKey: ['system-status'] })
                queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
              }}
            >
              <RotateCcw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            
            <Button
              variant="outline"
              size="sm"
              onClick={handleCleanupAlerts}
              disabled={cleanupAlertsMutation.isPending}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Cleanup Alerts
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}