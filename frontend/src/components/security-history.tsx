"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
  ChevronUp
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const EVENT_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
}> = {
  login_success: { icon: LogIn, label: "Connexion réussie", variant: "default" },
  login_failed: { icon: ShieldAlert, label: "Connexion échouée", variant: "destructive" },
  "2fa_enabled": { icon: ShieldCheck, label: "2FA activée", variant: "default" },
  "2fa_disabled": { icon: ShieldOff, label: "2FA désactivée", variant: "secondary" },
  "2fa_recovery_code_used": { icon: Key, label: "Code de récupération utilisé", variant: "outline" },
  email_changed: { icon: Mail, label: "Email modifié", variant: "outline" },
  profile_updated: { icon: User, label: "Profil mis à jour", variant: "outline" },
  password_changed: { icon: Key, label: "Mot de passe modifié", variant: "default" },
  password_change_failed: { icon: AlertCircle, label: "Changement de mot de passe échoué", variant: "destructive" },
  user_approved: { icon: ShieldCheck, label: "Compte approuvé", variant: "default" },
  user_promoted: { icon: Shield, label: "Privilèges admin accordés", variant: "default" },
  user_demoted: { icon: ShieldOff, label: "Privilèges admin retirés", variant: "secondary" },
  user_deleted: { icon: ShieldAlert, label: "Compte supprimé", variant: "destructive" },
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
    relative = "À l'instant";
  } else if (diffMins < 60) {
    relative = `Il y a ${diffMins} minute${diffMins > 1 ? 's' : ''}`;
  } else if (diffHours < 24) {
    relative = `Il y a ${diffHours} heure${diffHours > 1 ? 's' : ''}`;
  } else if (diffDays < 7) {
    relative = `Il y a ${diffDays} jour${diffDays > 1 ? 's' : ''}`;
  } else {
    relative = date.toLocaleDateString('fr-FR', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  }

  const fullDate = date.toLocaleString('fr-FR', {
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
        return data.method === "2fa" ? "Connexion avec 2FA" : "Connexion par mot de passe";
      
      case "login_failed":
        if (data.reason === "unknown_email") return "Échec : email inconnu";
        if (data.reason === "invalid_password") return "Échec : mot de passe incorrect";
        if (data.reason === "invalid_2fa_code") return "Échec : code 2FA incorrect";
        return `Échec : ${data.reason}`;
      
      case "2fa_recovery_code_used":
        return `Code de récupération utilisé (${data.remaining_codes} restant${data.remaining_codes > 1 ? 's' : ''})`;
      
      case "email_changed":
        return `Nouvel email : ${data.new_email}`;
      
      case "profile_updated":
        return `Champs modifiés : ${data.fields?.join(', ') || 'profil'}`;
      
      case "password_change_failed":
        return data.reason === "invalid_current_password" 
          ? "Échec : mot de passe actuel incorrect" 
          : `Échec : ${data.reason}`;
      
      case "user_approved":
        return `Approuvé par admin #${data.approved_by_admin_id}`;
      
      case "user_promoted":
        return `Promu admin par #${data.admin_id}`;
      
      case "user_demoted":
        return `Rétrogradé par admin #${data.admin_id}`;
      
      case "user_deleted":
        return `Supprimé par admin #${data.deleted_by_admin_id}`;
      
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
    queryFn: () => apiClient.getUserAuditLogs(50),
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
            Historique de sécurité
          </CardTitle>
          <CardDescription>
            Vos 50 derniers événements de sécurité
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
            Historique de sécurité
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Impossible de charger l'historique de sécurité
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
          Historique de sécurité
        </CardTitle>
        <CardDescription>
          {logs.length > 0 
            ? `Vos ${logs.length} derniers événements de sécurité (conservés ${process.env.NEXT_PUBLIC_AUDIT_RETENTION_DAYS || 365} jours)`
            : "Aucun événement enregistré"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {logs.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            Aucun événement de sécurité enregistré
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

                return (
                  <div key={log.id}>
                    <div className="flex items-start gap-4">
                      <div className="mt-0.5">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={config.variant} className="font-medium">
                            {config.label}
                          </Badge>
                          <span className="text-xs text-muted-foreground ml-auto">
                            {formatDate(log.created_at)}
                          </span>
                          {(log.ip_address || log.user_agent) && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 ml-2"
                              onClick={() => toggleExpanded(log.id)}
                            >
                              {isExpanded ? (
                                <ChevronUp className="h-3 w-3" />
                              ) : (
                                <ChevronDown className="h-3 w-3" />
                              )}
                            </Button>
                          )}
                        </div>
                        {contextualMessage && (
                          <p className="text-sm text-foreground">
                            {contextualMessage}
                          </p>
                        )}
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
