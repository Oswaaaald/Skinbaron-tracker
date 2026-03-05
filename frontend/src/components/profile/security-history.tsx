"use client"

import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from "@/lib/constants"
import { AUDIT_EVENT_CONFIG } from "@/lib/audit-icons"
import { formatEventData } from "@/lib/formatters"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { 
  Shield, 
  ArrowRight
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LogListSkeleton } from "@/components/ui/skeletons"
import { usePageVisible } from "@/hooks/use-page-visible"
import { useAuth } from "@/contexts/auth-context"
import { useExpandableRows, LogEntryRow, LogScrollArea } from "@/components/log-entry-list"

export function SecurityHistory() {
  const { expandedIds, toggle } = useExpandableRows();
  const isVisible = usePageVisible();
  const { isReady, isAuthenticated } = useAuth();

  const { data, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.USER_AUDIT_LOGS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserAuditLogs(50), 'Failed to load audit logs'),
    enabled: isReady && isAuthenticated,
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
  });

  const logs = useMemo(() => data?.data ?? [], [data]);

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
          <LogListSkeleton />
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

  return (
    <Card>
      <CardHeader className="pb-3">
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
        <Separator className="mb-4" />
        <LogScrollArea empty={logs.length === 0} emptyMessage="No security events recorded">
          {logs.map((log: AuditLog, index: number) => {
            const config = AUDIT_EVENT_CONFIG[log.event_type] || {
              icon: Shield,
              label: log.event_type,
              variant: "outline" as const,
            };

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
                adminUsername = String(data['admin_username']) || null;
              } catch {}
            }

            return (
              <LogEntryRow
                key={log.id}
                icon={config.icon}
                badgeLabel={config.label}
                badgeVariant={config.variant}
                date={log.created_at}
                ipAddress={log.ip_address}
                userAgent={log.user_agent}
                expanded={expandedIds.has(log.id)}
                onToggleExpand={() => toggle(log.id)}
                isLast={index === logs.length - 1}
              >
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
              </LogEntryRow>
            );
          })}
        </LogScrollArea>
      </CardContent>
    </Card>
  );
}
