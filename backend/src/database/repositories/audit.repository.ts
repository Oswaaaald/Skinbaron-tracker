import type Database from 'better-sqlite3';

export interface AuditLog {
  id: number;
  user_id: number;
  event_type: string;
  event_data: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
}

export interface AdminAction {
  id: number;
  admin_user_id: number;
  admin_username: string;
  action: string;
  target_user_id: number | null;
  target_username: string | null;
  details: string;
  created_at: string;
}

export class AuditRepository {
  constructor(private db: Database.Database) {}

  // Audit logs
  createAuditLog(
    userId: number,
    eventType: string,
    eventData?: string,
    ipAddress?: string,
    userAgent?: string
  ): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log (user_id, event_type, event_data, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(userId, eventType, eventData || null, ipAddress || null, userAgent || null);
  }

  getAuditLogsByUserId(userId: number, limit: number = 100): AuditLog[] {
    const stmt = this.db.prepare(`
      SELECT * FROM audit_log 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ?
    `);
    const logs = stmt.all(userId, limit) as AuditLog[];
    
    // Collect all admin IDs to avoid N+1 query problem
    const adminIds = new Set<number>();
    logs.forEach(log => {
      if (log.event_data && typeof log.event_data === 'string') {
        try {
          const data = JSON.parse(log.event_data) as Record<string, unknown>;
          const adminId = data['admin_id'] || data['approved_by_admin_id'] || data['deleted_by_admin_id'];
          if (adminId && typeof adminId === 'number') {
            adminIds.add(adminId);
          }
        } catch {
          // Invalid JSON, skip
        }
      }
    });

    // Fetch all admin usernames in a single query
    const adminMap = new Map<number, string>();
    if (adminIds.size > 0) {
      const placeholders = Array.from(adminIds).map(() => '?').join(',');
      const adminStmt = this.db.prepare(`SELECT id, username FROM users WHERE id IN (${placeholders})`);
      const admins = adminStmt.all(...Array.from(adminIds)) as Array<{ id: number; username: string }>;
      admins.forEach(admin => adminMap.set(admin.id, admin.username));
    }

    // Enrich logs with admin usernames
    return logs.map(log => {
      if (log.event_data && typeof log.event_data === 'string') {
        try {
          const data = JSON.parse(log.event_data) as Record<string, unknown>;
          const adminId = data['admin_id'] || data['approved_by_admin_id'] || data['deleted_by_admin_id'];
          
          if (adminId && typeof adminId === 'number') {
            const adminUsername = adminMap.get(adminId);
            if (adminUsername) {
              log.event_data = JSON.stringify({
                ...data,
                admin_username: adminUsername
              });
            }
          }
        } catch {
          // Invalid JSON, leave as is
        }
      }
      return log;
    });
  }

  getAllAuditLogs(limit: number = 100, eventType?: string, userId?: number): Array<AuditLog & { username?: string; email?: string }> {
    let query = `
      SELECT 
        audit_log.*,
        users.username,
        users.email
      FROM audit_log
      LEFT JOIN users ON audit_log.user_id = users.id
      WHERE 1=1
    `;
    const params: (string | number)[] = [];

    if (eventType) {
      query += ' AND audit_log.event_type = ?';
      params.push(eventType);
    }

    if (userId) {
      query += ' AND audit_log.user_id = ?';
      params.push(userId);
    }

    query += ' ORDER BY audit_log.created_at DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(query);
    const logs = stmt.all(...params) as Array<AuditLog & { username?: string; email?: string }>;
    
    // Collect all admin IDs to avoid N+1 query problem
    const adminIds = new Set<number>();
    logs.forEach(log => {
      if (log.event_data && typeof log.event_data === 'string') {
        try {
          const data = JSON.parse(log.event_data) as Record<string, unknown>;
          const adminId = data['admin_id'] || data['approved_by_admin_id'] || data['deleted_by_admin_id'];
          if (adminId && typeof adminId === 'number') {
            adminIds.add(adminId);
          }
        } catch {
          // Invalid JSON, skip
        }
      }
    });

    // Fetch all admin usernames in a single query
    const adminMap = new Map<number, string>();
    if (adminIds.size > 0) {
      const placeholders = Array.from(adminIds).map(() => '?').join(',');
      const adminStmt = this.db.prepare(`SELECT id, username FROM users WHERE id IN (${placeholders})`);
      const admins = adminStmt.all(...Array.from(adminIds)) as Array<{ id: number; username: string }>;
      admins.forEach(admin => adminMap.set(admin.id, admin.username));
    }

    // Enrich logs with admin usernames
    return logs.map(log => {
      if (log.event_data && typeof log.event_data === 'string') {
        try {
          const data = JSON.parse(log.event_data) as Record<string, unknown>;
          const adminId = data['admin_id'] || data['approved_by_admin_id'] || data['deleted_by_admin_id'];
          
          if (adminId && typeof adminId === 'number') {
            const adminUsername = adminMap.get(adminId);
            if (adminUsername) {
              log.event_data = JSON.stringify({
                ...data,
                admin_username: adminUsername
              });
            }
          }
        } catch {
          // Invalid JSON, leave as is
        }
      }
      return log;
    });
  }

  cleanupOldAuditLogs(daysToKeep: number = 90): number {
    const stmt = this.db.prepare(`
      DELETE FROM audit_log 
      WHERE created_at < datetime('now', '-' || ? || ' days')
    `);
    const result = stmt.run(daysToKeep);
    return result.changes;
  }

  // Admin actions
  logAdminAction(adminUserId: number, action: string, targetUserId: number | null, details: string): void {
    const stmt = this.db.prepare(`
      INSERT INTO admin_actions (admin_user_id, action, target_user_id, details, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(adminUserId, action, targetUserId, details, new Date().toISOString());
  }

  getAdminLogs(limit: number = 50): AdminAction[] {
    const stmt = this.db.prepare(`
      SELECT 
        al.*,
        u1.username as admin_username,
        u2.username as target_username
      FROM admin_actions al
      LEFT JOIN users u1 ON al.admin_user_id = u1.id
      LEFT JOIN users u2 ON al.target_user_id = u2.id
      ORDER BY al.created_at DESC
      LIMIT ?
    `);
    
    return stmt.all(limit) as AdminAction[];
  }

  getSystemStats(): {
    total_users: number;
    total_admins: number;
    total_rules: number;
    total_alerts: number;
    total_webhooks: number;
  } {
    const stmt = this.db.prepare(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE is_approved = 1) as total_users,
        (SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_approved = 1) as total_admins,
        (SELECT COUNT(*) FROM rules) as total_rules,
        (SELECT COUNT(*) FROM alerts) as total_alerts,
        (SELECT COUNT(*) FROM user_webhooks) as total_webhooks
    `);

    return stmt.get() as {
      total_users: number;
      total_admins: number;
      total_rules: number;
      total_alerts: number;
      total_webhooks: number;
    };
  }
}
