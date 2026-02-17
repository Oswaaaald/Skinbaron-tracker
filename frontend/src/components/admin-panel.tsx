'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Activity, AlertCircle, ArrowUpDown, Ban, ChevronLeft, ChevronRight, Clock, History, Search, Shield, User, Users, Wrench } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { LoadingState } from '@/components/ui/loading-state'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { extractErrorMessage } from '@/lib/utils'
import { QUERY_KEYS, SLOW_POLL_INTERVAL, ADMIN_USERS_PAGE_SIZE } from '@/lib/constants'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AdminAuditLogs } from '@/components/admin-audit-logs'
import { AdminUserDetailDialog } from '@/components/admin-user-detail'
import { SystemStats } from '@/components/system-stats'
import { usePageVisible } from '@/hooks/use-page-visible'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useDebounce } from '@/hooks/use-debounce'

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
  is_restricted: boolean
  restriction_type: string | null
  restriction_expires_at: string | null
  created_at: string
  avatar_url: string | null
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
  const [pendingUserDialog, setpendingUserDialog] = useState<{ open: boolean; userId: number | null; action: 'approve' | 'reject' }>({
    open: false,
    userId: null,
    action: 'approve',
  })
  const [schedulerConfirmOpen, setSchedulerConfirmOpen] = useState(false)
  const [detailUserId, setDetailUserId] = useState<number | null>(null)
  const isVisible = usePageVisible()
  const { syncStats } = useSyncStats()

  // Pagination/sort/filter state
  const [page, setPage] = useState(0)
  const [sortBy, setSortBy] = useState<string>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [searchInput, setSearchInput] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const debouncedSearch = useDebounce(searchInput, 400)

  // Fetch users (paginated)
  const { data: usersResponse, isLoading: usersLoading, isFetching: usersFetching } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_USERS, page, sortBy, sortDir, debouncedSearch, roleFilter],
    queryFn: async () => {
      const res = await apiClient.getAdminUsers({
        limit: ADMIN_USERS_PAGE_SIZE,
        offset: page * ADMIN_USERS_PAGE_SIZE,
        sort_by: sortBy,
        sort_dir: sortDir,
        search: debouncedSearch || undefined,
        role: roleFilter,
      })
      if (!res.success) throw new Error(res.message || 'Failed to load users')
      return { users: (res.data ?? []) as AdminUser[], pagination: res.pagination }
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    placeholderData: (prev) => prev,
  })

  // Fetch pending users
  const { data: pendingUsersData } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_PENDING],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.getPendingUsers(), 'Failed to load pending users')
      return response.data
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
  })

  // Fetch global stats
  const { data: statsData } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_STATS],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/admin/stats'), 'Failed to load stats')
      return response.data as GlobalStats
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
  })

  // Approve user mutation
  const approveUserMutation = useApiMutation(
    (userId: number) => apiClient.approveUser(userId),
    {
      invalidateKeys: [[QUERY_KEYS.ADMIN_PENDING], [QUERY_KEYS.ADMIN_USERS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ADMIN_AUDIT_LOGS]],
      onSuccess: () => {
        toast({
          title: "✅ User approved",
          description: "User account has been approved and activated",
        })
        setpendingUserDialog({ open: false, userId: null, action: 'approve' })
      },
      onError: (error: unknown) => {
        toast({
          variant: "destructive",
          title: "❌ Failed to approve user",
          description: extractErrorMessage(error),
        })
      },
    }
  )

  // Reject user mutation
  const rejectUserMutation = useApiMutation(
    (userId: number) => apiClient.rejectUser(userId),
    {
      invalidateKeys: [[QUERY_KEYS.ADMIN_PENDING], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ADMIN_AUDIT_LOGS]],
      onSuccess: () => {
        toast({
          title: "✅ User rejected",
          description: "User registration has been rejected",
        })
        setpendingUserDialog({ open: false, userId: null, action: 'reject' })
      },
      onError: (error: unknown) => {
        toast({
          variant: "destructive",
          title: "❌ Failed to reject user",
          description: extractErrorMessage(error),
        })
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
      invalidateKeys: [[QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ALERTS], [QUERY_KEYS.ALERT_STATS], [QUERY_KEYS.SYSTEM_STATUS]],
      onSuccess: () => {
        toast({
          title: "✅ Scheduler executed",
          description: "Check completed. New alerts will appear shortly.",
        })
        void syncStats()
      },
      onError: (error) => {
        toast({
          variant: "destructive",
          title: "❌ Scheduler failed",
          description: extractErrorMessage(error),
        })
      },
    }
  )

  const toggleSort = (column: string) => {
    if (sortBy === column) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(column)
      setSortDir(column === 'created_at' ? 'desc' : 'asc')
    }
    setPage(0)
  }

  const usersData = usersResponse?.users
  const totalUsers = usersResponse?.pagination?.total ?? 0
  const totalPages = Math.ceil(totalUsers / ADMIN_USERS_PAGE_SIZE)

  const handleForceScheduler = () => {
    setSchedulerConfirmOpen(true)
  }

  const confirmScheduler = () => {
    forceSchedulerMutation.mutate()
  }

  if (usersLoading) {
    return <LoadingState variant="card" />
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
      <div className="grid gap-4 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsData?.total_users ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Admins</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsData?.total_admins ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsData?.total_rules ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsData?.total_alerts ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statsData?.total_webhooks ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabbed Navigation */}
      <Tabs defaultValue="users" className="w-full">
        <TabsList className="w-full flex">
          <TabsTrigger value="users" className="flex items-center gap-1.5"><Users className="h-4 w-4" /><span className="hidden sm:inline">Users</span></TabsTrigger>
          <TabsTrigger value="logs" className="flex items-center gap-1.5"><History className="h-4 w-4" /><span className="hidden sm:inline">Logs</span></TabsTrigger>
          {currentUser?.is_super_admin && (
            <TabsTrigger value="tools" className="flex items-center gap-1.5"><Wrench className="h-4 w-4" /><span className="hidden sm:inline">Tools</span></TabsTrigger>
          )}
          <TabsTrigger value="system" className="flex items-center gap-1.5"><Activity className="h-4 w-4" /><span className="hidden sm:inline">System</span></TabsTrigger>
        </TabsList>

        {/* Users Tab */}
        <TabsContent value="users" className="space-y-4 mt-4">
          <Card>
        <CardHeader>
          <CardTitle>User Management</CardTitle>
          <CardDescription>Manage users and their permissions</CardDescription>
        </CardHeader>
        <CardContent>
          {/* Search + filters */}
          <div className="flex flex-col sm:flex-row gap-3 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by username or email..."
                value={searchInput}
                onChange={(e) => { setSearchInput(e.target.value); setPage(0) }}
                className="pl-8"
              />
            </div>
            <Select value={roleFilter} onValueChange={(v) => { setRoleFilter(v); setPage(0) }}>
              <SelectTrigger className="w-full sm:w-[140px]">
                <SelectValue placeholder="All roles" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All roles</SelectItem>
                <SelectItem value="admin">Admins</SelectItem>
                <SelectItem value="user">Users</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="relative">
            {usersFetching && !usersLoading && (
              <div className="absolute inset-0 bg-background/50 z-10 flex items-center justify-center rounded-md">
                <LoadingSpinner size="sm" />
              </div>
            )}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('username')}>
                    <span className="flex items-center gap-1">Username <ArrowUpDown className="h-3 w-3" />{sortBy === 'username' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('email')}>
                    <span className="flex items-center gap-1">Email <ArrowUpDown className="h-3 w-3" />{sortBy === 'email' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('role')}>
                    <span className="flex items-center gap-1">Role <ArrowUpDown className="h-3 w-3" />{sortBy === 'role' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('rules')}>
                    <span className="flex items-center gap-1">Rules <ArrowUpDown className="h-3 w-3" />{sortBy === 'rules' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('alerts')}>
                    <span className="flex items-center gap-1">Alerts <ArrowUpDown className="h-3 w-3" />{sortBy === 'alerts' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('webhooks')}>
                    <span className="flex items-center gap-1">Webhooks <ArrowUpDown className="h-3 w-3" />{sortBy === 'webhooks' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                  <TableHead className="cursor-pointer select-none" onClick={() => toggleSort('created_at')}>
                    <span className="flex items-center gap-1">Joined <ArrowUpDown className="h-3 w-3" />{sortBy === 'created_at' && <span className="text-xs">({sortDir})</span>}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(!usersData || usersData.length === 0) && !usersLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      {debouncedSearch || roleFilter !== 'all' ? 'No users match your filters' : 'No users found'}
                    </TableCell>
                  </TableRow>
                ) : null}
                {usersData?.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">
                    <button
                      type="button"
                      className="hover:underline text-left cursor-pointer text-primary flex items-center gap-2"
                      onClick={() => setDetailUserId(user.id)}
                    >
                      {user.avatar_url ? (
                        <img
                          src={user.avatar_url}
                          alt=""
                          className="h-7 w-7 rounded-full object-cover shrink-0"
                        />
                      ) : (
                        <span className="h-7 w-7 rounded-full bg-muted flex items-center justify-center shrink-0">
                          <User className="h-3.5 w-3.5 text-muted-foreground" />
                        </span>
                      )}
                      {user.username}
                    </button>
                  </TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
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
                      {user.is_restricted && user.restriction_type === 'permanent' && (
                        <Badge variant="destructive" className="gap-1">
                          <Ban className="h-3 w-3" />
                          Restricted
                        </Badge>
                      )}
                      {user.is_restricted && user.restriction_type === 'temporary' && user.restriction_expires_at && new Date(user.restriction_expires_at) > new Date() && (
                        <Badge variant="secondary" className="gap-1 bg-orange-500/15 text-orange-600 dark:text-orange-400">
                          <Clock className="h-3 w-3" />
                          Restricted
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>{user.stats.rules_count}</TableCell>
                  <TableCell>{user.stats.alerts_count}</TableCell>
                  <TableCell>{user.stats.webhooks_count}</TableCell>
                  <TableCell>{new Date(user.created_at).toLocaleDateString('fr-FR', { 
                    day: '2-digit', 
                    month: '2-digit', 
                    year: 'numeric' 
                  })}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                Showing {page * ADMIN_USERS_PAGE_SIZE + 1}–{Math.min((page + 1) * ADMIN_USERS_PAGE_SIZE, totalUsers)} of {totalUsers} users
              </p>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                </Button>
                <span className="text-sm font-medium px-2">
                  {page + 1} / {totalPages}
                </span>
                <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
                  Next <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
          </CardContent>
          </Card>
        </TabsContent>

        {/* Logs Tab */}
        <TabsContent value="logs" className="space-y-4 mt-4">
          {currentUser?.is_admin && <AdminAuditLogs />}
        </TabsContent>

        {/* System Tab */}
        <TabsContent value="system" className="space-y-4 mt-4">
          <SystemStats enabled={true} />
        </TabsContent>

        {/* Tools Tab (Super Admin only) */}
        {currentUser?.is_super_admin && (
          <TabsContent value="tools" className="space-y-4 mt-4">
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
          </TabsContent>
        )}
      </Tabs>

      {/* Pending User Approval/Reject Dialog */}
      <ConfirmDialog
        open={pendingUserDialog.open}
        onOpenChange={(open) => setpendingUserDialog({ ...pendingUserDialog, open })}
        title={pendingUserDialog.action === 'approve' ? 'Approve User' : 'Reject User'}
        description={pendingUserDialog.action === 'approve'
          ? 'This user will be able to log in and use the application.'
          : 'This will permanently delete the user registration.'}
        confirmText={(approveUserMutation.isPending || rejectUserMutation.isPending) ? 'Processing...' : 'Confirm'}
        variant={pendingUserDialog.action === 'approve' ? 'default' : 'destructive'}
        onConfirm={() => {
          if (pendingUserDialog.userId) {
            if (pendingUserDialog.action === 'approve') {
              approveUserMutation.mutate(pendingUserDialog.userId)
            } else {
              rejectUserMutation.mutate(pendingUserDialog.userId)
            }
          }
        }}
      />

      {/* Scheduler Confirmation Dialog */}
      <ConfirmDialog
        open={schedulerConfirmOpen}
        onOpenChange={setSchedulerConfirmOpen}
        title="Run Scheduler"
        description="Force the scheduler to run now? This will check all enabled rules immediately."
        confirmText="Run Now"
        variant="default"
        onConfirm={confirmScheduler}
      />

      {/* User Detail Dialog (GDPR-audited) */}
      <AdminUserDetailDialog
        userId={detailUserId}
        open={detailUserId !== null}
        onOpenChange={(open) => { if (!open) setDetailUserId(null) }}
      />
    </div>
  )
}
