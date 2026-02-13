"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { QUERY_KEYS, AUDIT_EVENT_CONFIG } from "@/lib/constants"
import { formatRelativeDate, formatEventData } from "@/lib/formatters"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { 
  Shield, 
  ChevronDown,
  ChevronUp,
  ArrowRight
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LoadingState } from "@/components/ui/loading-state"
import { usePageVisible } from "@/hooks/use-page-visible"

export function SecurityHistory() {
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set());
  const isVisible = usePageVisible();

  const { data, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.USER_AUDIT_LOGS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserAuditLogs(50), 'Failed to load audit logs'),
    refetchInterval: isVisible ? 60000 : false, // Refresh every minute when visible
  });

  const toggleExpanded = (logId: number) => {
    const newExpanded = new Set(expandedLogs);
    if (newExpanded.has(logId)) {
      newExpanded.delete(logId);
    } else {
      newExpanded.add(logId);
    }
    setExpandedLogs(newExpanded);
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security History
          </CardTitle>
          <CardDescription>
            Your last 50 security events
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LoadingState variant="inline" />
        </CardContent>
      </Card>
    );
  }

  if (error || !data?.success) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Unable to load security history
          </p>
        </CardContent>
      </Card>
    );
  }

  const logs = data.data || [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Security History
        </CardTitle>
        <CardDescription>
          {logs.length > 0 
            ? `Your last ${logs.length} security events (retained for ${process.env['NEXT_PUBLIC_AUDIT_RETENTION_DAYS'] || 365} days)`
            : "No events recorded"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {logs.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No security events recorded
          </p>
        ) : (
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {logs.map((log: AuditLog, index: number) => {
                const config = AUDIT_EVENT_CONFIG[log.event_type] || {
                  icon: Shield,
                  label: log.event_type,
                  variant: "outline" as const,
                };
                
                const Icon = config.icon;
                const isExpanded = expandedLogs.has(log.id);
                const contextualMessage = formatEventData(log.event_type, log.event_data);

                // For user_deleted events, extract deleted user info from event_data
                let displayUsername = null;
                let displayEmail = null;
                let adminUsername = null;
                if (log.event_type === 'user_deleted') {
                  try {
                    const data = JSON.parse(log.event_data || '{}') as Record<string, unknown>;
                    displayUsername = String(data['username']);
                    displayEmail = String(data['email']);
                    // For user_deleted, the current log user is the admin who did the deletion
                    // We need to get admin info from a different source since this is the user's own audit log
                    adminUsername = String(data['admin_username']) || null;
                  } catch {}
                }

                return (
                  <div key={log.id}>
                    <div 
                      className={`flex items-start gap-4 ${(log.ip_address || log.user_agent) ? 'cursor-pointer hover:bg-muted/50 -mx-2 px-2 py-1 rounded-md transition-colors' : ''}`}
                      onClick={(log.ip_address || log.user_agent) ? () => toggleExpanded(log.id) : undefined}
                    >
                      <div className="mt-0.5">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={config.variant} className="font-medium">
                            {config.label}
                          </Badge>
                          {log.event_type === 'user_deleted' && displayUsername && (
                            <>
                              <Badge variant="secondary" className="font-semibold">
                                {displayUsername}
                              </Badge>
                              {displayEmail && (
                                <span className="text-xs text-muted-foreground">
                                  {displayEmail}
                                </span>
                              )}
                              {adminUsername && (
                                <>
                                  <ArrowRight className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-sm text-foreground">
                                    Deleted by {adminUsername}
                                  </span>
                                </>
                              )}
                            </>
                          )}
                          {contextualMessage && (
                            <>
                              <ArrowRight className="h-3 w-3 text-muted-foreground" />
                              <span className="text-sm text-foreground">
                                {contextualMessage}
                              </span>
                            </>
                          )}
                          <span className="text-xs text-muted-foreground ml-auto">
                            {formatRelativeDate(log.created_at)}
                          </span>
                          {(log.ip_address || log.user_agent) && (
                            <div className="h-6 px-2 ml-2 flex items-center">
                              {isExpanded ? (
                                <ChevronUp className="h-3 w-3" />
                              ) : (
                                <ChevronDown className="h-3 w-3" />
                              )}
                            </div>
                          )}
                        </div>
                        {isExpanded && (
                          <div className="flex flex-col gap-1 pt-1 text-xs text-muted-foreground/60">
                            {log.ip_address && (
                              <span className="font-mono">IP: {log.ip_address}</span>
                            )}
                            {log.user_agent && (
                              <span className="font-mono break-all">
                                {log.user_agent}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    {index < logs.length - 1 && <Separator className="mt-4" />}
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
