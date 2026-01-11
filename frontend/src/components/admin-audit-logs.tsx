"use client"

import { useState } from "react"
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
  ShieldAlert, 
  LogIn, 
  Key, 
  Mail, 
  User,
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  Search,
  X
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const EVENT_TYPES = [
  { value: "", label: "All Events" },
  { value: "login_success", label: "Login Success" },
  { value: "login_failed", label: "Login Failed" },
  { value: "2fa_enabled", label: "2FA Enabled" },
  { value: "2fa_disabled", label: "2FA Disabled" },
  { value: "2fa_recovery_code_used", label: "2FA Recovery Used" },
  { value: "email_changed", label: "Email Changed" },
  { value: "profile_updated", label: "Profile Updated" },
  { value: "password_changed", label: "Password Changed" },
  { value: "password_change_failed", label: "Password Change Failed" },
  { value: "user_approved", label: "User Approved" },
  { value: "user_promoted", label: "User Promoted" },
  { value: "user_demoted", label: "User Demoted" },
  { value: "user_deleted", label: "User Deleted" },
];

const EVENT_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
}> = {
  login_success: { icon: LogIn, label: "Login Success", variant: "default" },
  login_failed: { icon: ShieldAlert, label: "Login Failed", variant: "destructive" },
  "2fa_enabled": { icon: ShieldCheck, label: "2FA Enabled", variant: "default" },
  "2fa_disabled": { icon: ShieldOff, label: "2FA Disabled", variant: "secondary" },
  "2fa_recovery_code_used": { icon: Key, label: "Recovery Code Used", variant: "outline" },
  email_changed: { icon: Mail, label: "Email Changed", variant: "outline" },
  profile_updated: { icon: User, label: "Profile Updated", variant: "outline" },
  password_changed: { icon: Key, label: "Password Changed", variant: "default" },
  password_change_failed: { icon: AlertCircle, label: "Password Change Failed", variant: "destructive" },
  user_approved: { icon: ShieldCheck, label: "User Approved", variant: "default" },
  user_promoted: { icon: Shield, label: "User Promoted", variant: "default" },
  user_demoted: { icon: ShieldOff, label: "User Demoted", variant: "secondary" },
  user_deleted: { icon: ShieldAlert, label: "User Deleted", variant: "destructive" },
};

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function AdminAuditLogs() {
  const [eventType, setEventType] = useState<string>("");
  const [userId, setUserId] = useState<string>("");
  const [limit, setLimit] = useState<number>(100);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['admin-audit-logs', eventType, userId, limit],
    queryFn: () => apiClient.getAllAuditLogs({
      limit,
      event_type: eventType || undefined,
      user_id: userId ? parseInt(userId) : undefined,
    }),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const handleClearFilters = () => {
    setEventType("");
    setUserId("");
    setLimit(100);
  };

  if (isLoading) {
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
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Security Audit Logs (Super Admin)
        </CardTitle>
        <CardDescription>
          {logs.length > 0 
            ? `${logs.length} security events - Auto-deleted after ${process.env.NEXT_PUBLIC_AUDIT_RETENTION_DAYS || 365} days (GDPR)`
            : "No security events recorded"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="grid gap-4 md:grid-cols-4">
          <div className="space-y-2">
            <Label htmlFor="event-type">Event Type</Label>
            <Select value={eventType} onValueChange={setEventType}>
              <SelectTrigger id="event-type">
                <SelectValue placeholder="All Events" />
              </SelectTrigger>
              <SelectContent>
                {EVENT_TYPES.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="user-id">User ID</Label>
            <Input
              id="user-id"
              type="number"
              placeholder="Filter by user ID"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            />
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

          <div className="space-y-2">
            <Label>&nbsp;</Label>
            <div className="flex gap-2">
              <Button onClick={() => refetch()} variant="outline" size="icon">
                <Search className="h-4 w-4" />
              </Button>
              <Button onClick={handleClearFilters} variant="outline" size="icon">
                <X className="h-4 w-4" />
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
                const config = EVENT_CONFIG[log.event_type] || {
                  icon: AlertCircle,
                  label: log.event_type,
                  variant: "outline" as const,
                };
                
                const Icon = config.icon;
                const eventData = log.event_data ? JSON.parse(log.event_data) : {};

                return (
                  <div key={log.id}>
                    <div className="flex items-start gap-4">
                      <div className="mt-0.5">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={config.variant}>
                            {config.label}
                          </Badge>
                          <Badge variant="outline">
                            User #{log.user_id}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatDate(log.created_at)}
                          </span>
                        </div>
                        {log.event_data && (
                          <p className="text-sm text-muted-foreground font-mono text-xs">
                            {log.event_data}
                          </p>
                        )}
                        <div className="flex gap-4 text-xs text-muted-foreground/60">
                          {log.ip_address && <span>IP: {log.ip_address}</span>}
                          {log.user_agent && (
                            <span className="truncate max-w-md" title={log.user_agent}>
                              {log.user_agent}
                            </span>
                          )}
                        </div>
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
