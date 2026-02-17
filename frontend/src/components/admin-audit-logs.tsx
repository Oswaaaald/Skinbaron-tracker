"use client"

import { useState, useEffect } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { 
  Shield, 
  X,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  ArrowRight
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { usePageVisible } from "@/hooks/use-page-visible"
import { LoadingState } from "@/components/ui/loading-state"
import { QUERY_KEYS, SLOW_POLL_INTERVAL, AUDIT_EVENT_TYPES, AUDIT_EVENT_CONFIG } from "@/lib/constants"
import { formatRelativeDate, formatEventData } from "@/lib/formatters"

export function AdminAuditLogs() {
  const [eventType, setEventType] = useState<string>("all");
  const [userSearch, setUserSearch] = useState<string>("");
  const [selectedUser, setSelectedUser] = useState<{ id: number; username: string; email: string } | null>(null);
  const [showSuggestions, setShowSuggestions] = useState<boolean>(false);
  const [limit, setLimit] = useState<number>(100);
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set());
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

  const toggleExpanded = (logId: number) => {
    const newExpanded = new Set(expandedLogs);
    if (newExpanded.has(logId)) {
      newExpanded.delete(logId);
    } else {
      newExpanded.add(logId);
    }
    setExpandedLogs(newExpanded);
  };

  const initialLoading = isLoading && !data;

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

  const logs = data.data || [];

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
        {/* Filters */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="space-y-2">
            <Label htmlFor="event-type">Event Type</Label>
            <Select value={eventType} onValueChange={setEventType}>
              <SelectTrigger id="event-type">
                <SelectValue placeholder="All Events" />
              </SelectTrigger>
              <SelectContent>
                {AUDIT_EVENT_TYPES.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2 relative">
            <Label htmlFor="user-search">Search User</Label>
            <div className="relative">
              <Input
                id="user-search"
                type="text"
                placeholder="Search by username or email..."
                value={userSearch}
                onChange={(e) => handleUserSearchChange(e.target.value)}
                onClick={(e) => {
                  e.stopPropagation();
                  if (userSearch.length >= 2) setShowSuggestions(true);
                }}
                className={selectedUser ? "pr-8" : ""}
                autoComplete="off"
                data-form-type="other"
                data-lpignore="true"
                data-1p-ignore="true"
                name="user-search-filter"
              />
              {selectedUser && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleClearUserFilter();
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            {showSuggestions && searchResults?.data && searchResults.data.length > 0 && (
              <div className="absolute z-50 w-full mt-1 bg-popover border rounded-md shadow-lg max-h-60 overflow-auto">
                {searchResults.data.map((user) => (
                  <button
                    key={user.id}
                    type="button"
                    className="w-full px-3 py-2 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer border-b last:border-b-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleSelectUser(user);
                    }}
                  >
                    <div className="font-medium">{user.username}</div>
                    <div className="text-xs text-muted-foreground">{user.email}</div>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="limit">Limit</Label>
            <Select value={limit.toString()} onValueChange={(v) => setLimit(parseInt(v))}>
              <SelectTrigger id="limit">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="50">50 events</SelectItem>
                <SelectItem value="100">100 events</SelectItem>
                <SelectItem value="250">250 events</SelectItem>
                <SelectItem value="500">500 events</SelectItem>
                <SelectItem value="1000">1000 events</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2 flex flex-col">
            <Label className="invisible">Actions</Label>
            <div className="flex items-end gap-2">
              <Button onClick={() => void refetch()} variant="outline" className="flex-1" disabled={isFetching}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
              </Button>
              <Button onClick={handleClearFilters} variant="outline" className="flex-1">
                <X className="h-4 w-4 mr-2" />
                Clear Filters
              </Button>
            </div>
          </div>
        </div>

        <Separator />

        {/* Logs Display */}
        {logs.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No security events found
          </p>
        ) : (
          <ScrollArea className="h-[600px] pr-4">
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
                          <span className="text-xs text-muted-foreground ml-auto">
                            {formatRelativeDate(log.created_at, 'fr')}
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
