'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { AlertCircle, Shield, ShieldOff, Trash2, Users } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

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
  const queryClient = useQueryClient()
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; user: AdminUser | null }>({
    open: false,
    user: null,
  })
  const [adminDialog, setAdminDialog] = useState<{ open: boolean; user: AdminUser | null; action: 'grant' | 'revoke' }>({
    open: false,
    user: null,
    action: 'grant',
  })

  // Fetch users
  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      const response = await apiClient.get('/api/admin/users')
      return response.data as AdminUser[]
    },
  })

  // Fetch global stats
  const { data: statsData } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: async () => {
      const response = await apiClient.get('/api/admin/stats')
      return response.data as GlobalStats
    },
  })

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      await apiClient.delete(`/api/admin/users/${userId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      setDeleteDialog({ open: false, user: null })
    },
  })

  // Toggle admin mutation
  const toggleAdminMutation = useMutation({
    mutationFn: async ({ userId, isAdmin }: { userId: number; isAdmin: boolean }) => {
      await apiClient.patch(`/api/admin/users/${userId}/admin`, { is_admin: isAdmin })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      // Force all connected users to refresh their profile immediately
      window.dispatchEvent(new CustomEvent('user-profile-changed'))
      setAdminDialog({ open: false, user: null, action: 'grant' })
    },
  })

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

  if (usersLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
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
                      <Badge variant="default" className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600">
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
                      {user.is_admin ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleToggleAdmin(user, 'revoke')}
                          disabled={
                            toggleAdminMutation.isPending || 
                            isCurrentUser(user) || 
                            isLastAdmin() ||
                            user.is_super_admin
                          }
                          title={
                            user.is_super_admin
                              ? "Cannot revoke super admin status"
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
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleToggleAdmin(user, 'grant')}
                          disabled={toggleAdminMutation.isPending}
                        >
                          <Shield className="h-4 w-4 mr-1" />
                          Make Admin
                        </Button>
                      )}
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => handleDeleteUser(user)}
                        disabled={
                          deleteUserMutation.isPending || 
                          isCurrentUser(user) ||
                          user.is_super_admin
                        }
                        title={
                          user.is_super_admin
                            ? "Cannot delete super admin"
                            : isCurrentUser(user)
                            ? "You cannot delete your own account"
                            : undefined
                        }
                      >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Delete
                      </Button>
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
    </div>
  )
}
