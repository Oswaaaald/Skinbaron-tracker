'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { AlertCircle, Shield, ShieldOff, Trash2, Users } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { AdminAuditLogs } from '@/components/admin-audit-logs'

interface UserStats {
  rules_count: number
  alerts_count: number
  webhooks_count: number
}

interface AdminUser {
  id: number
  username: string
  email: string
  is_admin: boolean
  is_super_admin: boolean
  created_at: string
  stats: UserStats
}

interface GlobalStats {
  total_users: number
  total_admins: number
  total_rules: number
  total_alerts: number
  total_webhooks: number
}

export function AdminPanel() {
  const { user: currentUser } = useAuth()
  const { toast } = useToast()
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; user: AdminUser | null }>({
    open: false,
    user: null,
  })
  const [adminDialog, setAdminDialog] = useState<{ open: boolean; user: AdminUser | null; action: 'grant' | 'revoke' }>({
    open: false,
    user: null,
    action: 'grant',
  })
  const [pendingUserDialog, setpendingUserDialog] = useState<{ open: boolean; userId: number | null; action: 'approve' | 'reject' }>({
    open: false,
    userId: null,
    action: 'approve',
  })

  // Fetch users
  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/admin/users'), 'Failed to load users')
      return response.data as AdminUser[]
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
  })

  // Fetch pending users
  const { data: pendingUsersData } = useQuery({
    queryKey: ['admin', 'pendingUsers'],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.getPendingUsers(), 'Failed to load pending users')
      return response.data
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
  })

  // Fetch global stats
  const { data: statsData } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/admin/stats'), 'Failed to load stats')
      return response.data as GlobalStats
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
  })

  // Delete user mutation
  const deleteUserMutation = useApiMutation(
    (userId: number) => apiClient.delete(`/api/admin/users/${userId}`),
    {
      invalidateKeys: [['admin', 'users'], ['admin', 'stats'], ['admin-audit-logs']],
      onSuccess: () => {
        setDeleteDialog({ open: false, user: null })
      },
    }
  )

  // Toggle admin mutation
  const toggleAdminMutation = useApiMutation(
    ({ userId, isAdmin }: { userId: number; isAdmin: boolean }) =>
      apiClient.patch(`/api/admin/users/${userId}/admin`, { is_admin: isAdmin }),
    {
      invalidateKeys: [['admin', 'users'], ['admin', 'stats'], ['admin-audit-logs']],
      onSuccess: () => {
        // Force all connected users to refresh their profile immediately
        window.dispatchEvent(new CustomEvent('user-profile-changed'))
        setAdminDialog({ open: false, user: null, action: 'grant' })
      },
    }
  )

  // Approve user mutation
  const approveUserMutation = useApiMutation(
    (userId: number) => apiClient.approveUser(userId),
    {
      invalidateKeys: [['admin', 'pendingUsers'], ['admin', 'users'], ['admin', 'stats'], ['admin-audit-logs']],
      onSuccess: () => {
        setpendingUserDialog({ open: false, userId: null, action: 'approve' })
      },
    }
  )

  // Reject user mutation
  const rejectUserMutation = useApiMutation(
    (userId: number) => apiClient.rejectUser(userId),
    {
      invalidateKeys: [['admin', 'pendingUsers'], ['admin', 'stats'], ['admin-audit-logs']],
      onSuccess: () => {
        setpendingUserDialog({ open: false, userId: null, action: 'reject' })
      },
    }
  )

  // Force scheduler mutation (super admin only)
  const forceSchedulerMutation = useApiMutation(
    async () => {
      const response = await apiClient.forceSchedulerRun()
      if (!response.success) {
        throw new Error(response.error || 'Failed to run scheduler')
      }
      return response
    },
    {
      invalidateKeys: [['admin', 'stats']],
      onSuccess: () => {
        toast({
          title: "✅ Scheduler executed",
          description: "Alerts have been checked successfully",
        })
      },
      onError: (error) => {
        toast({
          variant: "destructive",
          title: "❌ Scheduler failed",
          description: error instanceof Error ? error.message : 'Unknown error',
        })
      },
    }
  )

  const isCurrentUser = (user: AdminUser) => {
    return currentUser?.email === user.email
  }

  const isLastAdmin = () => {
    return statsData?.total_admins === 1
  }

  const handleDeleteUser = (user: AdminUser) => {
    setDeleteDialog({ open: true, user })
  }

  const handleToggleAdmin = (user: AdminUser, action: 'grant' | 'revoke') => {
    setAdminDialog({ open: true, user, action })
  }

  const confirmDelete = () => {
    if (deleteDialog.user) {
      deleteUserMutation.mutate(deleteDialog.user.id)
    }
  }

  const confirmToggleAdmin = () => {
    if (adminDialog.user) {
      const isAdmin = adminDialog.action === 'grant'
      toggleAdminMutation.mutate({ userId: adminDialog.user.id, isAdmin })
    }
  }

  const handleForceScheduler = () => {
    if (confirm('Force the scheduler to run now? This will check all enabled rules immediately.')) {
      forceSchedulerMutation.mutate()
    }
  }

  if (usersLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Pending Users Section */}
      {pendingUsersData && pendingUsersData.length > 0 && (
        <Card className="border-orange-500 border-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-orange-500" />
              Pending Approvals ({pendingUsersData.length})
            </CardTitle>
            <CardDescription>New user registrations awaiting approval</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Registered</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pendingUsersData.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.username}</TableCell>
                    <TableCell>{user.email}</TableCell>
                    <TableCell>{new Date(user.created_at).toLocaleDateString('fr-FR')}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="default"
                          size="sm"
                          onClick={() => setpendingUserDialog({ open: true, userId: user.id, action: 'approve' })}
                          disabled={approveUserMutation.isPending}
                        >
                          Approve
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => setpendingUserDialog({ open: true, userId: user.id, action: 'reject' })}
                          disabled={rejectUserMutation.isPending}
                        >
                          Reject
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Global Stats */}
      {statsData && (
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.total_users}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Admins</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.total_admins}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Rules</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.total_rules}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.total_alerts}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statsData.total_webhooks}</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Super Admin Actions */}
      {currentUser?.is_super_admin && (
        <Card className="border-purple-500 border-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-purple-500" />
              Super Admin Actions
            </CardTitle>
            <CardDescription>Advanced system controls</CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              onClick={() => handleForceScheduler()}
              disabled={forceSchedulerMutation.isPending}
              variant="outline"
            >
              {forceSchedulerMutation.isPending ? 'Running...' : 'Force Scheduler Run'}
            </Button>
            <p className="text-sm text-muted-foreground mt-2">
              Bypass the cron schedule and run the scheduler immediately
            </p>
          </CardContent>
        </Card>
      )}

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>User Management</CardTitle>
          <CardDescription>Manage users and their permissions</CardDescription>
        </CardHeader>
        <CardContent>
          {deleteUserMutation.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                {(deleteUserMutation.error as any).response?.data?.message || 'Failed to delete user'}
              </AlertDescription>
            </Alert>
          )}
          {toggleAdminMutation.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                {(toggleAdminMutation.error as any).response?.data?.message || 'Failed to update admin status'}
              </AlertDescription>
            </Alert>
          )}

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Rules</TableHead>
                <TableHead>Alerts</TableHead>
                <TableHead>Webhooks</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {usersData?.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    {user.is_super_admin ? (
                      <Badge variant="default" className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600 text-white">
                        <Shield className="h-3 w-3" />
                        Super Admin
                      </Badge>
                    ) : user.is_admin ? (
                      <Badge variant="default" className="gap-1">
                        <Shield className="h-3 w-3" />
                        Admin
                      </Badge>
                    ) : (
                      <Badge variant="outline">User</Badge>
                    )}
                  </TableCell>
                  <TableCell>{user.stats.rules_count}</TableCell>
                  <TableCell>{user.stats.alerts_count}</TableCell>
                  <TableCell>{user.stats.webhooks_count}</TableCell>
                  <TableCell>{new Date(user.created_at).toLocaleDateString('fr-FR', { 
                    day: '2-digit', 
                    month: '2-digit', 
                    year: 'numeric' 
                  })}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      {user.is_super_admin ? (
                        // Super Admin - show locked state
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled
                            className="opacity-40 cursor-not-allowed"
                            title="Cannot revoke super admin status"
                          >
                            <ShieldOff className="h-4 w-4 mr-1" />
                            Protected
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled
                            className="opacity-40 cursor-not-allowed"
                            title="Cannot delete super admin"
                          >
                            <Trash2 className="h-4 w-4 mr-1" />
                            Protected
                          </Button>
                        </>
                      ) : user.is_admin ? (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleToggleAdmin(user, 'revoke')}
                            disabled={
                              toggleAdminMutation.isPending || 
                              isCurrentUser(user) || 
                              isLastAdmin() ||
                              !currentUser?.is_super_admin
                            }
                            title={
                              !currentUser?.is_super_admin
                                ? "Only super administrators can manage admin privileges"
                                : isCurrentUser(user)
                                ? "You cannot revoke your own admin status"
                                : isLastAdmin()
                                ? "Cannot revoke the last admin"
                                : undefined
                            }
                          >
                            <ShieldOff className="h-4 w-4 mr-1" />
                            Revoke Admin
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDeleteUser(user)}
                            disabled={
                              deleteUserMutation.isPending || 
                              isCurrentUser(user) ||
                              !currentUser?.is_super_admin
                            }
                            title={
                              !currentUser?.is_super_admin
                                ? "Only super administrators can delete other administrators"
                                : isCurrentUser(user)
                                ? "You cannot delete your own account"
                                : undefined
                            }
                          >
                            <Trash2 className="h-4 w-4 mr-1" />
                            Delete
                          </Button>
                        </>
                      ) : (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleToggleAdmin(user, 'grant')}
                            disabled={toggleAdminMutation.isPending || !currentUser?.is_super_admin}
                            title={
                              !currentUser?.is_super_admin
                                ? "Only super administrators can grant admin privileges"
                                : undefined
                            }
                          >
                            <Shield className="h-4 w-4 mr-1" />
                            Make Admin
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDeleteUser(user)}
                            disabled={deleteUserMutation.isPending}
                          >
                            <Trash2 className="h-4 w-4 mr-1" />
                            Delete
                          </Button>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog.open} onOpenChange={(open) => setDeleteDialog({ ...deleteDialog, open })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <strong>{deleteDialog.user?.username}</strong>?
              This will permanently delete their account and all associated data (rules, alerts, webhooks).
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialog({ open: false, user: null })}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deleteUserMutation.isPending}>
              {deleteUserMutation.isPending ? <LoadingSpinner size="sm" /> : 'Delete User'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Admin Toggle Confirmation Dialog */}
      <Dialog open={adminDialog.open} onOpenChange={(open) => setAdminDialog({ ...adminDialog, open })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {adminDialog.action === 'grant' ? 'Grant Admin Access' : 'Revoke Admin Access'}
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to {adminDialog.action === 'grant' ? 'grant' : 'revoke'} administrator privileges{' '}
              {adminDialog.action === 'grant' ? 'to' : 'from'} <strong>{adminDialog.user?.username}</strong>?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAdminDialog({ open: false, user: null, action: 'grant' })}>
              Cancel
            </Button>
            <Button onClick={confirmToggleAdmin} disabled={toggleAdminMutation.isPending}>
              {toggleAdminMutation.isPending ? <LoadingSpinner size="sm" /> : 'Confirm'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Pending User Approval/Reject Dialog */}
      <Dialog open={pendingUserDialog.open} onOpenChange={(open) => setpendingUserDialog({ ...pendingUserDialog, open })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pendingUserDialog.action === 'approve' ? 'Approve User' : 'Reject User'}
            </DialogTitle>
            <DialogDescription>
              {pendingUserDialog.action === 'approve' 
                ? 'This user will be able to log in and use the application.'
                : 'This will permanently delete the user registration.'}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setpendingUserDialog({ open: false, userId: null, action: 'approve' })}>
              Cancel
            </Button>
            <Button 
              variant={pendingUserDialog.action === 'approve' ? 'default' : 'destructive'}
              onClick={() => {
                if (pendingUserDialog.userId) {
                  if (pendingUserDialog.action === 'approve') {
                    approveUserMutation.mutate(pendingUserDialog.userId)
                  } else {
                    rejectUserMutation.mutate(pendingUserDialog.userId)
                  }
                }
              }}
              disabled={approveUserMutation.isPending || rejectUserMutation.isPending}
            >
              {(approveUserMutation.isPending || rejectUserMutation.isPending) ? <LoadingSpinner size="sm" /> : 'Confirm'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Super Admin Audit Logs Section */}
      {currentUser?.is_super_admin && <AdminAuditLogs />}
    </div>
  )
}
