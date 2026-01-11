"use client"

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
  AlertCircle
} from "lucide-react"
import { apiClient, type AuditLog } from "@/lib/api"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const EVENT_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
  description: (data: any) => string;
}> = {
  login_success: {
    icon: LogIn,
    label: "Connexion réussie",
    variant: "default",
    description: (data) => data?.method === "2fa" ? "avec 2FA" : "par mot de passe",
  },
  login_failed: {
    icon: ShieldAlert,
    label: "Connexion échouée",
    variant: "destructive",
    description: (data) => {
      if (data?.reason === "invalid_password") return "mot de passe incorrect";
      if (data?.reason === "invalid_2fa_code") return "code 2FA incorrect";
      if (data?.reason === "unknown_email") return "email inconnu";
      return "raison inconnue";
    },
  },
  "2fa_enabled": {
    icon: ShieldCheck,
    label: "2FA activée",
    variant: "default",
    description: () => "Authentification à deux facteurs activée",
  },
  "2fa_disabled": {
    icon: ShieldOff,
    label: "2FA désactivée",
    variant: "secondary",
    description: () => "Authentification à deux facteurs désactivée",
  },
  "2fa_recovery_code_used": {
    icon: Key,
    label: "Code de récupération utilisé",
    variant: "outline",
    description: (data) => `${data?.remaining_codes || 0} code(s) restant(s)`,
  },
  email_changed: {
    icon: Mail,
    label: "Email modifié",
    variant: "outline",
    description: (data) => `Nouvel email: ${data?.new_email || "N/A"}`,
  },
  profile_updated: {
    icon: User,
    label: "Profil mis à jour",
    variant: "outline",
    description: (data) => {
      const fields = data?.fields || [];
      return fields.length > 0 ? `Champs: ${fields.join(", ")}` : "Modifications du profil";
    },
  },
  password_changed: {
    icon: Key,
    label: "Mot de passe modifié",
    variant: "default",
    description: () => "Mot de passe changé avec succès",
  },
  password_change_failed: {
    icon: AlertCircle,
    label: "Changement de mot de passe échoué",
    variant: "destructive",
    description: (data) => data?.reason === "invalid_current_password" 
      ? "mot de passe actuel incorrect" 
      : "erreur inconnue",
  },
  user_approved: {
    icon: ShieldCheck,
    label: "Compte approuvé",
    variant: "default",
    description: () => "Votre compte a été approuvé par un administrateur",
  },
  user_promoted: {
    icon: Shield,
    label: "Privilèges administrateur accordés",
    variant: "default",
    description: () => "Vous avez reçu des privilèges administrateur",
  },
  user_demoted: {
    icon: ShieldOff,
    label: "Privilèges administrateur retirés",
    variant: "secondary",
    description: () => "Vos privilèges administrateur ont été retirés",
  },
  user_deleted: {
    icon: ShieldAlert,
    label: "Compte supprimé",
    variant: "destructive",
    description: () => "Votre compte a été supprimé",
  },
};

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  
  // Less than 1 minute
  if (diff < 60000) {
    return "À l'instant";
  }
  
  // Less than 1 hour
  if (diff < 3600000) {
    const minutes = Math.floor(diff / 60000);
    return `Il y a ${minutes} minute${minutes > 1 ? 's' : ''}`;
  }
  
  // Less than 24 hours
  if (diff < 86400000) {
    const hours = Math.floor(diff / 3600000);
    return `Il y a ${hours} heure${hours > 1 ? 's' : ''}`;
  }
  
  // Less than 7 days
  if (diff < 604800000) {
    const days = Math.floor(diff / 86400000);
    return `Il y a ${days} jour${days > 1 ? 's' : ''}`;
  }
  
  // Format as date
  return date.toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'short',
    year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function SecurityHistory() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['user-audit-logs'],
    queryFn: () => apiClient.getUserAuditLogs(50),
    refetchInterval: 60000, // Refresh every minute
  });

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
                  description: () => "Événement inconnu",
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
                        <div className="flex items-center gap-2">
                          <Badge variant={config.variant}>
                            {config.label}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatDate(log.created_at)}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {config.description(eventData)}
                        </p>
                        {log.ip_address && (
                          <p className="text-xs text-muted-foreground/60">
                            IP: {log.ip_address}
                          </p>
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
