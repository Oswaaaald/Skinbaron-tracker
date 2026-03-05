"use client"

import { useState, useEffect, useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { 
  Shield, 
  ArrowRight
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { usePageVisible } from "@/hooks/use-page-visible"
import { LogListSkeleton } from "@/components/ui/skeletons"
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from "@/lib/constants"
import { AUDIT_EVENT_CONFIG } from "@/lib/audit-icons"
import { formatEventData } from "@/lib/formatters"
import { useExpandableRows, LogEntryRow, LogScrollArea } from "@/components/log-entry-list"
import { AdminAuditLogsFilters } from "./audit-logs-filters"

export function AdminAuditLogs() {
  const [eventType, setEventType] = useState<string>("all");
  const [userSearch, setUserSearch] = useState<string>("");
  const [selectedUser, setSelectedUser] = useState<{ id: number; username: string; email: string } | null>(null);
  const [showSuggestions, setShowSuggestions] = useState<boolean>(false);
  const [limit, setLimit] = useState<number>(100);
  const { expandedIds, toggle } = useExpandableRows();
  const isVisible = usePageVisible();

  // Search users with debounce
  const { data: searchResults } = useQuery({
    queryKey: [QUERY_KEYS.SEARCH_USERS, userSearch],
    queryFn: async () => {
      if (userSearch.length < 2) return { success: true, data: [] };
      return apiClient.ensureSuccess(await apiClient.searchUsers(userSearch), 'Failed to search users');
    },
    enabled: userSearch.length >= 2,
    staleTime: 30000,
  });

  // Hide suggestions when clicking outside
  useEffect(() => {
    if (!showSuggestions) return;
    
    const handleClickOutside = () => setShowSuggestions(false);
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [showSuggestions]);

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_AUDIT_LOGS, eventType, selectedUser?.id, limit],
    queryFn: async () => {
      const result = apiClient.ensureSuccess(await apiClient.getAllAuditLogs({
        limit,
        event_type: eventType === "all" ? undefined : eventType,
        user_id: selectedUser?.id,
      }), 'Failed to load audit logs');
      return result;
    },
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
    notifyOnChangeProps: ['data', 'error'],
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    placeholderData: (prev) => prev,
    staleTime: 0,
    gcTime: 0,
  });

  const handleClearFilters = () => {
    setEventType("all");
    handleClearUserFilter();
    setLimit(100);
  };

  const handleSelectUser = (user: { id: number; username: string; email: string }) => {
    setSelectedUser(user);
    setUserSearch(`${user.username} (${user.email})`);
    setShowSuggestions(false);
  };

  const handleUserSearchChange = (value: string) => {
    setUserSearch(value);
    // Don't clear selectedUser while typing - only when explicitly cleared
    setShowSuggestions(true);
  };

  const handleClearUserFilter = () => {
    setUserSearch("");
    setSelectedUser(null);
    setShowSuggestions(false);
  };

  const initialLoading = isLoading && !data;
  const logs = useMemo(() => data?.data ?? [], [data]);

  if (initialLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security Audit Logs (Super Admin)
          </CardTitle>
          <CardDescription>
            All security events across all users
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LogListSkeleton withFilters />
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
            Security Audit Logs
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Failed to load audit logs
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
          Security Audit Logs (Super Admin)
        </CardTitle>
        <CardDescription>
          {logs.length > 0 
            ? `${logs.length} security events - Auto-deleted after ${process.env['NEXT_PUBLIC_AUDIT_RETENTION_DAYS'] || 365} days (GDPR)`
            : "No security events recorded"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isFetching && (
          <div className="text-xs text-muted-foreground">Refreshing...</div>
        )}
        <AdminAuditLogsFilters
          eventType={eventType}
          onEventTypeChange={setEventType}
          userSearch={userSearch}
          selectedUser={selectedUser}
          showSuggestions={showSuggestions}
          suggestions={searchResults?.data ?? []}
          limit={limit}
          isFetching={isFetching}
          onUserSearchChange={handleUserSearchChange}
          onUserInputClick={() => {
            if (userSearch.length >= 2) setShowSuggestions(true)
          }}
          onSelectUser={handleSelectUser}
          onClearUserFilter={handleClearUserFilter}
          onLimitChange={setLimit}
          onRefresh={() => { void refetch() }}
          onClearFilters={handleClearFilters}
        />

        <Separator />

        {/* Logs Display */}
        <LogScrollArea empty={logs.length === 0} emptyMessage="No security events found">
          {logs.map((log: AuditLog, index: number) => {
            const config = AUDIT_EVENT_CONFIG[log.event_type] || {
              icon: Shield,
              label: log.event_type,
              variant: "outline" as const,
            };

            const contextualMessage = formatEventData(log.event_type, log.event_data);

            // For user_deleted events, extract deleted user info from event_data
            let displayUsername = log.username;
            let displayEmail = log.email;
            if (log.event_type === 'user_deleted') {
              try {
                const data = JSON.parse(log.event_data || '{}') as Record<string, unknown>;
                displayUsername = String(data['username']) || log.username;
                displayEmail = String(data['email']) || log.email;
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
                <Badge variant="secondary" className="font-semibold">
                  {displayUsername || `User #${log.user_id}`}
                </Badge>
                {displayEmail && (
                  <span className="text-xs text-muted-foreground">
                    {displayEmail}
                  </span>
                )}
                {contextualMessage && (
                  <>
                    <ArrowRight className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm text-foreground">
                      {contextualMessage}
                    </span>
                  </>
                )}
                {log.event_type === 'user_deleted' && (
                  <>
                    <ArrowRight className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm text-foreground">
                      Deleted by {log.username || `admin #${log.user_id}`}
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
