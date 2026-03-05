'use client'

import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, History, Shield, Users, Wrench } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { QUERY_KEYS, SLOW_POLL_INTERVAL, ADMIN_USERS_PAGE_SIZE } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'
import { useAuth } from '@/contexts/auth-context'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useDebounce } from '@/hooks/use-debounce'
import { usePageVisible } from '@/hooks/use-page-visible'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useToast } from '@/hooks/use-toast'
import { AdminPanelSkeleton } from '@/components/ui/skeletons'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AdminActionLogs } from '@/components/admin/logs/action-logs'
import { AdminAuditLogs } from '@/components/admin/logs/audit-logs'
import { AdminPanelDialogs } from '@/components/admin/panel/dialogs'
import { AdminPanelPendingUsers, type PendingUser } from '@/components/admin/panel/pending-users'
import { AdminPanelStatsCards, type GlobalStats } from '@/components/admin/panel/stats-cards'
import { AdminPanelToolsTab } from '@/components/admin/panel/tools-tab'
import { AdminPanelUsersTab } from '@/components/admin/panel/users-tab'
import { AdminUserDetailDialog } from '@/components/admin/user-detail'
import { SystemStats } from '@/components/system/stats'

export function AdminPanel() {
  const { user: currentUser } = useAuth()
  const { toast } = useToast()
  const isVisible = usePageVisible()
  const { syncStats } = useSyncStats()

  const [pendingUserDialog, setPendingUserDialog] = useState<{ open: boolean; userId: number | null; action: 'approve' | 'reject' }>({
    open: false,
    userId: null,
    action: 'approve',
  })
  const [schedulerConfirmOpen, setSchedulerConfirmOpen] = useState(false)
  const [sentryConfirmOpen, setSentryConfirmOpen] = useState(false)
  const [detailUserId, setDetailUserId] = useState<number | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  const [page, setPage] = useState(0)
  const [sortBy, setSortBy] = useState('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [searchInput, setSearchInput] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const debouncedSearch = useDebounce(searchInput, 400)

  const { data: usersResponse, isLoading: usersLoading, isFetching: usersFetching } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_USERS, page, sortBy, sortDir, debouncedSearch, roleFilter, statusFilter],
    queryFn: async () => {
      const res = await apiClient.getAdminUsers({
        limit: ADMIN_USERS_PAGE_SIZE,
        offset: page * ADMIN_USERS_PAGE_SIZE,
        sort_by: sortBy,
        sort_dir: sortDir,
        search: debouncedSearch || undefined,
        role: roleFilter,
        status: statusFilter,
      })
      if (!res.success) throw new Error(res.message || 'Failed to load users')
      return { users: res.data ?? [], pagination: res.pagination }
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    placeholderData: (prev) => prev,
  })

  const { data: pendingUsersData } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_PENDING],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.getPendingUsers(), 'Failed to load pending users')
      return response.data as PendingUser[]
    },
    staleTime: 0,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
  })

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

  const approveUserMutation = useApiMutation(
    (userId: number) => apiClient.approveUser(userId),
    {
      invalidateKeys: [[QUERY_KEYS.ADMIN_PENDING], [QUERY_KEYS.ADMIN_USERS], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ADMIN_AUDIT_LOGS]],
      onSuccess: () => {
        toast({ title: '✅ User approved', description: 'User account has been approved and activated' })
        setPendingUserDialog((prev) => ({ ...prev, open: false }))
        setTimeout(() => setPendingUserDialog({ open: false, userId: null, action: 'approve' }), 200)
      },
      onError: (error: unknown) => {
        toast({
          variant: 'destructive',
          title: '❌ Failed to approve user',
          description: extractErrorMessage(error),
        })
      },
    }
  )

  const rejectUserMutation = useApiMutation(
    (userId: number) => apiClient.rejectUser(userId),
    {
      invalidateKeys: [[QUERY_KEYS.ADMIN_PENDING], [QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ADMIN_AUDIT_LOGS]],
      onSuccess: () => {
        toast({ title: '✅ User rejected', description: 'User registration has been rejected' })
        setPendingUserDialog((prev) => ({ ...prev, open: false }))
        setTimeout(() => setPendingUserDialog({ open: false, userId: null, action: 'approve' }), 200)
      },
      onError: (error: unknown) => {
        toast({
          variant: 'destructive',
          title: '❌ Failed to reject user',
          description: extractErrorMessage(error),
        })
      },
    }
  )

  const forceSchedulerMutation = useApiMutation(
    async () => {
      const response = await apiClient.forceSchedulerRun()
      if (!response.success) throw new Error(response.error || 'Failed to run scheduler')
      return response
    },
    {
      invalidateKeys: [[QUERY_KEYS.ADMIN_STATS], [QUERY_KEYS.ALERTS], [QUERY_KEYS.ALERT_STATS], [QUERY_KEYS.SYSTEM_STATUS]],
      onSuccess: () => {
        toast({ title: '✅ Scheduler executed', description: 'Check completed. New alerts will appear shortly.' })
        void syncStats()
      },
      onError: (error) => {
        toast({ variant: 'destructive', title: '❌ Scheduler failed', description: extractErrorMessage(error) })
      },
    }
  )

  const testSentryMutation = useApiMutation(
    async () => {
      const response = await apiClient.testSentry()
      if (!response.success) throw new Error(response.error || 'Failed to test Sentry')
      return response
    },
    {
      onSuccess: () => {
        toast({ title: '✅ Sentry test sent', description: 'Check your Sentry dashboard for the test error.' })
      },
      onError: (error) => {
        toast({ variant: 'destructive', title: '❌ Sentry test failed', description: extractErrorMessage(error) })
      },
    }
  )

  const toggleSort = useCallback((column: string) => {
    if (sortBy === column) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortBy(column)
      setSortDir(column === 'created_at' ? 'desc' : 'asc')
    }
    setPage(0)
  }, [sortBy])

  const usersData = usersResponse?.users
  const totalUsers = usersResponse?.pagination?.total ?? 0
  const totalPages = Math.ceil(totalUsers / ADMIN_USERS_PAGE_SIZE)

  if (usersLoading) return <AdminPanelSkeleton />

  return (
    <div className="space-y-6">
      <AdminPanelPendingUsers
        pendingUsers={pendingUsersData ?? []}
        pendingUserDialog={pendingUserDialog}
        setPendingUserDialog={setPendingUserDialog}
        approvePending={approveUserMutation.isPending}
        rejectPending={rejectUserMutation.isPending}
      />

      <AdminPanelStatsCards statsData={statsData} />

      <Tabs defaultValue="users" className="w-full">
        <TabsList className="w-full flex">
          <TabsTrigger value="users" className="flex items-center gap-1.5"><Users className="h-4 w-4" /><span className="hidden sm:inline">Users</span></TabsTrigger>
          <TabsTrigger value="logs" className="flex items-center gap-1.5"><History className="h-4 w-4" /><span className="hidden sm:inline">Audit Logs</span></TabsTrigger>
          {currentUser?.is_super_admin && <TabsTrigger value="admin-logs" className="flex items-center gap-1.5"><Shield className="h-4 w-4" /><span className="hidden sm:inline">Admin Logs</span></TabsTrigger>}
          {currentUser?.is_super_admin && <TabsTrigger value="tools" className="flex items-center gap-1.5"><Wrench className="h-4 w-4" /><span className="hidden sm:inline">Tools</span></TabsTrigger>}
          <TabsTrigger value="system" className="flex items-center gap-1.5"><Activity className="h-4 w-4" /><span className="hidden sm:inline">System</span></TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="space-y-4 mt-4">
          <AdminPanelUsersTab
            usersData={usersData}
            usersLoading={usersLoading}
            usersFetching={usersFetching}
            searchInput={searchInput}
            roleFilter={roleFilter}
            statusFilter={statusFilter}
            debouncedSearch={debouncedSearch}
            sortBy={sortBy}
            sortDir={sortDir}
            page={page}
            totalPages={totalPages}
            totalUsers={totalUsers}
            setSearchInput={setSearchInput}
            setRoleFilter={setRoleFilter}
            setStatusFilter={setStatusFilter}
            setPage={setPage}
            toggleSort={toggleSort}
            onOpenUserDetail={(id) => {
              setDetailUserId(id)
              setDetailOpen(true)
            }}
          />
        </TabsContent>

        <TabsContent value="logs" className="space-y-4 mt-4">
          {currentUser?.is_admin && <AdminAuditLogs />}
        </TabsContent>

        {currentUser?.is_super_admin && (
          <TabsContent value="admin-logs" className="space-y-4 mt-4">
            <AdminActionLogs />
          </TabsContent>
        )}

        <TabsContent value="system" className="space-y-4 mt-4">
          <SystemStats enabled={true} />
        </TabsContent>

        {currentUser?.is_super_admin && (
          <TabsContent value="tools" className="space-y-4 mt-4">
            <AdminPanelToolsTab
              sentryEnabled={statsData?.sentryEnabled}
              forceSchedulerPending={forceSchedulerMutation.isPending}
              testSentryPending={testSentryMutation.isPending}
              onForceScheduler={() => setSchedulerConfirmOpen(true)}
              onOpenSentryConfirm={() => setSentryConfirmOpen(true)}
            />
          </TabsContent>
        )}
      </Tabs>

      <AdminPanelDialogs
        pendingUserDialog={pendingUserDialog}
        setPendingUserDialog={setPendingUserDialog}
        approvePending={approveUserMutation.isPending}
        rejectPending={rejectUserMutation.isPending}
        onApprove={(userId) => approveUserMutation.mutate(userId)}
        onReject={(userId) => rejectUserMutation.mutate(userId)}
        schedulerConfirmOpen={schedulerConfirmOpen}
        setSchedulerConfirmOpen={setSchedulerConfirmOpen}
        onConfirmScheduler={() => forceSchedulerMutation.mutate()}
        sentryConfirmOpen={sentryConfirmOpen}
        setSentryConfirmOpen={setSentryConfirmOpen}
        onConfirmSentry={() => testSentryMutation.mutate()}
      />

      <AdminUserDetailDialog
        userId={detailUserId}
        open={detailOpen}
        onOpenChange={(open) => {
          setDetailOpen(open)
          if (!open) setTimeout(() => setDetailUserId(null), 200)
        }}
      />
    </div>
  )
}
