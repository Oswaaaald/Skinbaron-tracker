"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { 
  Shield, 
  ShieldAlert, 
  LogIn, 
  Key, 
  Mail, 
  User,
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  ArrowRight
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const EVENT_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
}> = {
  login_success: { icon: LogIn, label: "Login Success", variant: "default" },
  login_failed: { icon: ShieldAlert, label: "Login Failed", variant: "destructive" },
  logout: { icon: LogIn, label: "Logout", variant: "secondary" },
  "2fa_enabled": { icon: ShieldCheck, label: "2FA Enabled", variant: "default" },
  "2fa_disabled": { icon: ShieldOff, label: "2FA Disabled", variant: "secondary" },
  "2fa_recovery_code_used": { icon: Key, label: "Recovery Code Used", variant: "outline" },
  email_changed: { icon: Mail, label: "Email Changed", variant: "outline" },
  profile_updated: { icon: User, label: "Profile Updated", variant: "outline" },
  password_changed: { icon: Key, label: "Password Changed", variant: "default" },
  password_change_failed: { icon: AlertCircle, label: "Password Change Failed", variant: "destructive" },
  user_approved: { icon: ShieldCheck, label: "Account Approved", variant: "default" },
  user_promoted: { icon: Shield, label: "Promoted to Admin", variant: "default" },
  user_demoted: { icon: ShieldOff, label: "Admin Privileges Revoked", variant: "secondary" },
  user_deleted: { icon: ShieldAlert, label: "Account Deleted", variant: "destructive" },
};

function formatDate(dateString: string): string {
  // SQLite returns dates without timezone (e.g., "2026-01-11 23:37:14")
  // We need to append 'Z' to treat it as UTC, then convert to local time
  const utcDate = dateString.includes('Z') ? dateString : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  
  const diffMins = Math.floor(diff / 60000);
  const diffHours = Math.floor(diff / 3600000);
  const diffDays = Math.floor(diff / 86400000);

  let relative = "";
  if (diffMins < 1) {
    relative = "Just now";
  } else if (diffMins < 60) {
    relative = `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  } else if (diffHours < 24) {
    relative = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  } else if (diffDays < 7) {
    relative = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
  } else {
    relative = date.toLocaleDateString('en-US', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  }

  const fullDate = date.toLocaleString('en-US', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  return `${relative} • ${fullDate}`;
}

function formatEventData(eventType: string, eventDataJson: string | null): string {
  if (!eventDataJson) return "";

  try {
    const data = JSON.parse(eventDataJson);

    switch (eventType) {
      case "login_success":
        return data.method === "2fa" ? "Login with 2FA" : "Login with password";
      
      case "login_failed":
        if (data.reason === "unknown_email") return "Failed: unknown email";
        if (data.reason === "invalid_password") return "Failed: invalid password";
        if (data.reason === "invalid_2fa_code") return "Failed: invalid 2FA code";
        return `Failed: ${data.reason}`;
      
      case "2fa_enabled":
        return "Two-factor authentication enabled";
      
      case "2fa_disabled":
        return "Two-factor authentication disabled";
      
      case "2fa_recovery_code_used":
        return `Recovery code used (${data.remaining_codes} remaining)`;
      
      case "email_changed":
        return `New email: ${data.new_email}`;
      
      case "profile_updated":
        return `Updated fields: ${data.fields?.join(', ') || 'profile'}`;
      
      case "password_change_failed":
        return data.reason === "invalid_current_password" 
          ? "Failed: invalid current password" 
          : `Failed: ${data.reason}`;
      
      case "user_approved":
        return `Approved by ${data.admin_username || `admin #${data.approved_by_admin_id}`}`;
      
      case "user_promoted":
        return `Promoted to admin by ${data.admin_username || `#${data.admin_id}`}`;
      
      case "user_demoted":
        return `Demoted by ${data.admin_username || `admin #${data.admin_id}`}`;
      
      case "user_deleted":
        // We'll show admin info separately
        return "";
      
      case "logout":
        return data.reason === "user_logout" ? "User logout" : "Logged out";
      
      default:
        return eventDataJson;
    }
  } catch {
    return eventDataJson;
  }
}

export function SecurityHistory() {
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set());

  const { data, isLoading, error } = useQuery({
    queryKey: ['user-audit-logs'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserAuditLogs(50), 'Failed to load audit logs'),
    refetchInterval: 60000, // Refresh every minute
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
          <div className="flex justify-center py-8">
            <LoadingSpinner />
          </div>
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
                const config = EVENT_CONFIG[log.event_type] || {
                  icon: AlertCircle,
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
                    const data = JSON.parse(log.event_data || '{}');
                    displayUsername = data.username;
                    displayEmail = data.email;
                    // For user_deleted, the current log user is the admin who did the deletion
                    // We need to get admin info from a different source since this is the user's own audit log
                    adminUsername = data.admin_username || null;
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
                            {formatDate(log.created_at)}
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
