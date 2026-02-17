import { FastifyInstance } from 'fastify';
import { store } from '../database/index.js';
import { getScheduler } from '../lib/scheduler.js';
import { getClientIp, getAuthUser, invalidateUserCache } from '../lib/middleware.js';
import { handleRouteError } from '../lib/validation-handler.js';
import { Errors } from '../lib/errors.js';
import { AuthService } from '../lib/auth.js';
import { appConfig } from '../lib/config.js';
import { deleteAvatarFile } from '../lib/avatar.js';

/**
 * Admin routes - All routes require admin privileges
 */
export default async function adminRoutes(fastify: FastifyInstance) {
  // Local hooks for defense in depth - ensures protection even if register preHandler is forgotten
  fastify.addHook('preHandler', fastify.authenticate);
  fastify.addHook('preHandler', fastify.requireAdmin);
  
  const scheduler = getScheduler();

  // Rate limiting for destructive admin operations
  const adminWriteRateLimit = {
    max: 10,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many admin operations. Please try again in 1 minute.',
    }),
  };

  /**
   * GET /api/admin/users - List all users (admin only) with pagination & sorting
   */
  fastify.get('/users', {
    schema: {
      description: 'List all users with pagination (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', default: 20, minimum: 1, maximum: 100 },
          offset: { type: 'integer', default: 0, minimum: 0 },
          sort_by: { type: 'string', enum: ['username', 'email', 'role', 'created_at', 'rules', 'alerts', 'webhooks'], default: 'created_at' },
          sort_dir: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          search: { type: 'string', maxLength: 200 },
          role: { type: 'string', enum: ['admin', 'user', 'all'], default: 'all' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  username: { type: 'string' },
                  email: { type: 'string' },
                  is_admin: { type: 'boolean' },
                  is_super_admin: { type: 'boolean' },
                  created_at: { type: 'string' },
                  stats: {
                    type: 'object',
                    properties: {
                      rules_count: { type: 'number' },
                      alerts_count: { type: 'number' },
                      webhooks_count: { type: 'number' },
                    },
                  },
                },
              },
            },
            pagination: {
              type: 'object',
              properties: {
                limit: { type: 'number' },
                offset: { type: 'number' },
                total: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const query = request.query as {
        limit?: number;
        offset?: number;
        sort_by?: 'username' | 'email' | 'role' | 'created_at' | 'rules' | 'alerts' | 'webhooks';
        sort_dir?: 'asc' | 'desc';
        search?: string;
        role?: 'admin' | 'user' | 'all';
      };

      const limit = query.limit ?? 20;
      const offset = query.offset ?? 0;

      const { data: usersWithStats, total } = await store.users.findAllWithStatsPaginated({
        limit,
        offset,
        sortBy: query.sort_by,
        sortDir: query.sort_dir,
        search: query.search,
        role: query.role,
      });

      const result = usersWithStats.map(user => ({
        id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin || false,
        is_super_admin: user.is_super_admin || false,
        created_at: user.created_at,
        avatar_url: user.avatar_filename
          ? `${appConfig.NEXT_PUBLIC_API_URL}/api/avatars/${user.avatar_filename}`
          : null,
        stats: user.stats,
      }));

      return reply.status(200).send({
        success: true,
        data: result,
        pagination: { limit, offset, total },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List users');
    }
  });

  /**
   * GET /api/admin/users/:id - View detailed user profile (admin only)
   * GDPR: Logged as admin data access. No secrets exposed (password, TOTP, recovery codes).
   */
  fastify.get('/users/:id', {
    schema: {
      description: 'View detailed user profile (admin only, GDPR-audited)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const adminId = getAuthUser(request).id;

      const user = await store.getUserById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      // Fetch related data in parallel
      const [oauthAccounts, passkeysData, rules, webhooks, userStats] = await Promise.all([
        store.oauth.findByUserId(id),
        store.passkeys.findByUserId(id),
        store.rules.findByUserId(id),
        store.webhooks.findByUserId(id, false), // don't decrypt webhook URLs
        store.audit.getUserStats(id),
      ]);

      // GDPR audit: log admin data access
      await store.logAdminAction(adminId, 'view_user_detail', id, `Viewed detailed profile of ${user.username} (${user.email})`);

      // Sanitize: never expose secrets
      return reply.status(200).send({
        success: true,
        data: {
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
          has_custom_avatar: !!user.avatar_filename,
          is_admin: user.is_admin || false,
          is_super_admin: user.is_super_admin || false,
          is_approved: user.is_approved || false,
          totp_enabled: user.totp_enabled || false,
          tos_accepted_at: user.tos_accepted_at,
          created_at: user.created_at,
          updated_at: user.updated_at,
          // Linked accounts (no tokens/secrets)
          oauth_accounts: oauthAccounts.map(a => ({
            id: a.id,
            provider: a.provider,
            provider_email: a.provider_email,
            created_at: a.created_at,
          })),
          // Passkeys (no public_key/credential_id)
          passkeys: passkeysData.map(p => ({
            id: p.id,
            name: p.name,
            device_type: p.device_type,
            backed_up: p.backed_up,
            created_at: p.created_at,
            last_used_at: p.last_used_at,
          })),
          // Stats
          stats: {
            rules_count: rules.length,
            active_rules_count: rules.filter(r => r.enabled).length,
            webhooks_count: webhooks.length,
            active_webhooks_count: webhooks.filter(w => w.is_active).length,
            alerts_count: userStats.totalAlerts,
          },
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'View user detail');
    }
  });

  /**
   * DELETE /api/admin/users/:id/avatar - Remove a user's custom avatar (admin only)
   * GDPR: Logged as admin data modification.
   */
  fastify.delete('/users/:id/avatar', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Remove a user\'s custom avatar (admin only, GDPR-audited)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const adminId = getAuthUser(request).id;

      const user = await store.getUserById(id);
      if (!user) throw Errors.notFound('User');

      if (!user.avatar_filename) {
        return reply.status(200).send({
          success: true,
          message: 'User has no custom avatar',
        });
      }

      // Delete file from disk
      await deleteAvatarFile(user.avatar_filename);

      // Clear in database
      await store.updateUser(id, { avatar_filename: null });

      // GDPR audit: log admin action
      await store.logAdminAction(adminId, 'admin_avatar_removed', id, `Removed custom avatar for ${user.username} (${user.email})`);

      // Also log in user's own audit trail
      await store.createAuditLog(id, 'avatar_removed', JSON.stringify({ removed_by_admin: adminId }), getClientIp(request), request.headers['user-agent']);

      return reply.status(200).send({
        success: true,
        message: 'User avatar removed successfully',
        data: {
          avatar_url: AuthService.getAvatarUrl({ ...user, avatar_filename: null }, appConfig.NEXT_PUBLIC_API_URL),
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Admin remove user avatar');
    }
  });

  /**
   * DELETE /api/admin/users/:id - Delete a user (admin only)
   */
  fastify.delete('/users/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Delete a user and all their data (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const adminId = getAuthUser(request).id;

      // Prevent deleting yourself
      if (id === adminId) {
        throw Errors.forbidden('You cannot delete your own account');
      }

      // Check if user exists
      const user = await store.getUserById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      // Prevent operating on pending users (they belong to the approvals flow)
      if (!user.is_approved) {
        throw Errors.forbidden('Pending users must be approved or rejected before they can be managed');
      }

      // Only super admins can delete admins
      if (user.is_admin) {
        const currentAdmin = await store.getUserById(adminId);
        if (!currentAdmin?.is_super_admin) {
          throw Errors.forbidden('Only super administrators can delete other administrators');
        }

        const adminCount = await store.users.countAdmins();
        
        if (adminCount <= 1) {
          throw Errors.badRequest('You cannot delete the last administrator account');
        }
      }

      // Log admin action BEFORE deleting user (for audit trail)
      await store.logAdminAction(adminId, 'delete_user', id, `Deleted user ${user.username} (${user.email})`);

      // Get admin info for the audit log
      const admin = await store.getUserById(adminId);

      // Create audit log for the ADMIN who performed the deletion
      await store.createAuditLog(
        adminId,  // Use admin's ID, not the deleted user's ID
        'user_deleted',
        JSON.stringify({ 
          deleted_user_id: id,
          deleted_by_admin_id: adminId,
          admin_username: admin?.username,
          username: user.username,
          email: user.email 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

      // Revoke all refresh tokens so the user cannot obtain new access tokens
      await store.revokeAllRefreshTokensForUser(id);

      // Invalidate user cache so the auth middleware immediately rejects requests
      invalidateUserCache(id);

      // Clean up avatar file from disk before deleting user
      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      // Delete user (CASCADE will handle rules, alerts, webhooks)
      const deleted = await store.deleteUser(id);

      if (!deleted) {
        throw Errors.internal('Failed to delete user');
      }

      return reply.status(200).send({
        success: true,
        message: `User ${user.username} deleted successfully`,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete user');
    }
  });

  /**
   * PATCH /api/admin/users/:id/admin - Toggle admin status (admin only)
   */
  fastify.patch('/users/:id/admin', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Toggle admin status for a user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
      body: {
        type: 'object',
        required: ['is_admin'],
        properties: {
          is_admin: { type: 'boolean' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                username: { type: 'string' },
                is_admin: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const { is_admin } = request.body as { is_admin: boolean };
      const adminId = getAuthUser(request).id;

      // Prevent modifying your own admin status
      if (id === adminId) {
        throw Errors.forbidden('You cannot change your own administrator privileges');
      }

      // Check if user exists
      const user = await store.getUserById(id);
      if (!user) {
        throw Errors.notFound('User');
      }

      // Pending users should be handled via approval flow, not admin toggles
      if (!user.is_approved) {
        throw Errors.forbidden('Cannot change admin status for a pending user');
      }

      // Only super admins can grant or revoke admin status to/from admins
      if (user.is_admin || is_admin) {
        const currentAdmin = await store.getUserById(adminId);
        if (!currentAdmin?.is_super_admin) {
          throw Errors.forbidden('Only super administrators can manage admin privileges');
        }
      }

      // Prevent modifying admin status of super admins (would create inconsistent state)
      if (user.is_super_admin) {
        throw Errors.forbidden('Cannot modify administrator privileges of a super administrator');
      }

      // If removing admin, check if this is the last admin
      if (user.is_admin && !is_admin) {
        const adminCount = await store.users.countAdmins();
        
        if (adminCount <= 1) {
          throw Errors.badRequest('You cannot remove administrator privileges from the last admin');
        }
      }

      // Toggle admin status
      const updated = await store.toggleUserAdmin(id, is_admin);

      if (!updated) {
        throw Errors.internal('Failed to update admin status');
      }

      // Invalidate cached user data so middleware picks up new admin status immediately
      invalidateUserCache(id);

      // Log admin action
      const action = is_admin ? 'grant_admin' : 'revoke_admin';
      const details = `${is_admin ? 'Granted' : 'Revoked'} admin privileges for ${user.username}`;
      await store.logAdminAction(adminId, action, id, details);

      // Create audit log
      const eventType = is_admin ? 'user_promoted' : 'user_demoted';
      await store.createAuditLog(
        id,
        eventType,
        JSON.stringify({ 
          admin_id: adminId,
          is_admin 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: `Admin status updated for ${user.username}`,
        data: { is_admin },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Toggle admin status');
    }
  });

  /**
   * GET /api/admin/stats - Get global statistics (admin only)
   */
  fastify.get('/stats', {
    schema: {
      description: 'Get global statistics (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                users: { type: 'number' },
                admins: { type: 'number' },
                rules: { type: 'number' },
                enabled_rules: { type: 'number' },
                alerts: { type: 'number' },
                webhooks: { type: 'number' },
              },
              additionalProperties: true,
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const stats = await store.getGlobalStats();

      return reply.status(200).send({
        success: true,
        data: stats,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get global stats');
    }
  });

  /**
   * GET /api/admin/pending-users - Get users pending approval (admin only)
   */
  fastify.get('/pending-users', {
    schema: {
      description: 'Get users pending approval (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  username: { type: 'string' },
                  email: { type: 'string' },
                  created_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const pendingUsers = await store.getPendingUsers();

      return reply.status(200).send({
        success: true,
        data: pendingUsers,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get pending users');
    }
  });

  /**
   * POST /api/admin/approve-user/:id - Approve a pending user (admin only)
   */
  fastify.post('/approve-user/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Approve a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const success = await store.approveUser(id);

      if (!success) {
        throw Errors.notFound('User');
      }

      // Log admin action
      await store.logAdminAction(getAuthUser(request).id, 'approve_user', id, `Approved user ID ${id}`);

      // Create audit log
      await store.createAuditLog(
        id,
        'user_approved',
        JSON.stringify({ 
          approved_by_admin_id: getAuthUser(request).id 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: 'User approved successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Approve user');
    }
  });

  /**
   * POST /api/admin/reject-user/:id - Reject (delete) a pending user (admin only)
   */
  fastify.post('/reject-user/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Reject and delete a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };

      // Verify user exists and is actually pending approval
      const user = await store.getUserById(id);
      if (!user) {
        throw Errors.notFound('User');
      }
      if (user.is_approved) {
        throw Errors.forbidden('Only pending users can be rejected. Use the delete endpoint for approved users.');
      }

      // Log admin action BEFORE deleting so the FK to target_user_id is still valid
      await store.logAdminAction(getAuthUser(request).id, 'reject_user', id, `Rejected user ${user.username} (${user.email})`);

      const success = await store.rejectUser(id);

      if (!success) {
        throw Errors.notFound('User');
      }

      return reply.status(200).send({
        success: true,
        message: 'User rejected and deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Reject user');
    }
  });

  /**
   * POST /api/admin/scheduler/force-run - Force scheduler to run immediately (admin only)
   */
  fastify.post('/scheduler/force-run', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Force the scheduler to run immediately (bypasses cron schedule) - Admin only',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      // Force the scheduler to execute immediately
      await scheduler.forceRun();

      // Log admin action
      await store.logAdminAction(getAuthUser(request).id, 'force_scheduler', null, 'Manually triggered scheduler run');

      return reply.status(200).send({
        success: true,
        message: 'Scheduler executed successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Force scheduler run');
    }
  });

  /**
   * GET /api/admin/audit-logs/:userId - Get audit logs for a specific user (admin only)
   */
  fastify.get('/audit-logs/:userId', {
    schema: {
      description: 'Get security audit logs for a specific user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: {
          userId: { type: 'integer', minimum: 1 },
        },
        required: ['userId'],
      },
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 500 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                user: {
                  type: 'object',
                  properties: {
                    id: { type: 'number' },
                    username: { type: 'string' },
                    email: { type: 'string' },
                  },
                },
                logs: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      id: { type: 'number' },
                      event_type: { type: 'string' },
                      event_data: { type: 'string', nullable: true },
                      ip_address: { type: 'string', nullable: true },
                      user_agent: { type: 'string', nullable: true },
                      created_at: { type: 'string' },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { userId } = request.params as { userId: number };
      const { limit = 100 } = request.query as { limit?: number };

      const user = await store.getUserById(userId);
      if (!user) {
        throw Errors.notFound('User');
      }

      const logs = await store.getAuditLogsByUserId(userId, limit);

      return reply.status(200).send({
        success: true,
        data: {
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
          },
          logs,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get user audit logs');
    }
  });

  /**
   * GET /api/admin/audit-logs - Get all audit logs (admin only)
   */
  fastify.get('/audit-logs', {
    schema: {
      description: 'Get all security audit logs (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 1000 },
          event_type: { type: 'string', maxLength: 50 },
          user_id: { type: 'integer', minimum: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  user_id: { type: 'number' },
                  username: { type: 'string', nullable: true },
                  email: { type: 'string', nullable: true },
                  event_type: { type: 'string' },
                  event_data: { type: 'string', nullable: true },
                  ip_address: { type: 'string', nullable: true },
                  user_agent: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { limit = 100, event_type, user_id } = request.query as { limit?: number; event_type?: string; user_id?: number };

      const logs = await store.getAllAuditLogs(limit, event_type, user_id);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get audit logs');
    }
  });

  /**
   * GET /api/admin/users/search - Search users by username or email
   */
  fastify.get('/users/search', {
    schema: {
      description: 'Search users by username or email (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', minLength: 1, maxLength: 100 },
        },
        required: ['q'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  username: { type: 'string' },
                  email: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { q } = request.query as { q: string };
      const users = await store.searchUsers(q);

      return reply.status(200).send({
        success: true,
        data: users,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Search users');
    }
  });
}
