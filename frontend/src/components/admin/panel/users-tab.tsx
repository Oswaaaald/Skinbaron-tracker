'use client'

import { ArrowUpDown, Ban, ChevronLeft, ChevronRight, Clock, Search, Shield } from 'lucide-react'
import type { AdminUser } from '@/lib/api'
import { ADMIN_USERS_PAGE_SIZE } from '@/lib/constants'
import { formatDateOnly } from '@/lib/formatters'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { UserAvatar } from '@/components/ui/user-avatar'

interface AdminPanelUsersTabProps {
  usersData?: AdminUser[]
  usersLoading: boolean
  usersFetching: boolean
  searchInput: string
  roleFilter: string
  statusFilter: string
  debouncedSearch: string
  sortBy: string
  sortDir: 'asc' | 'desc'
  page: number
  totalPages: number
  totalUsers: number
  setSearchInput: (value: string) => void
  setRoleFilter: (value: string) => void
  setStatusFilter: (value: string) => void
  setPage: (value: number | ((prev: number) => number)) => void
  toggleSort: (column: string) => void
  onOpenUserDetail: (userId: number) => void
}

function SortableHeader({
  label,
  column,
  sortBy,
  sortDir,
  onSort,
}: {
  label: string
  column: string
  sortBy: string
  sortDir: 'asc' | 'desc'
  onSort: (column: string) => void
}) {
  return (
    <TableHead
      className="cursor-pointer select-none"
      role="button"
      tabIndex={0}
      onClick={() => onSort(column)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSort(column)
        }
      }}
    >
      <span className="flex items-center gap-1">
        {label}
        <ArrowUpDown className="h-3 w-3" />
        {sortBy === column && <span className="text-xs">({sortDir})</span>}
      </span>
    </TableHead>
  )
}

export function AdminPanelUsersTab({
  usersData,
  usersLoading,
  usersFetching,
  searchInput,
  roleFilter,
  statusFilter,
  debouncedSearch,
  sortBy,
  sortDir,
  page,
  totalPages,
  totalUsers,
  setSearchInput,
  setRoleFilter,
  setStatusFilter,
  setPage,
  toggleSort,
  onOpenUserDetail,
}: AdminPanelUsersTabProps) {
  return (
    <Card className="border-border/70 bg-card/92">
      <CardHeader>
        <CardTitle>User Management</CardTitle>
        <CardDescription>Manage users and their permissions</CardDescription>
      </CardHeader>
      <CardContent className="mt-2">
        <div className="flex flex-col sm:flex-row gap-3 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by username or email..."
              value={searchInput}
              onChange={(e) => {
                setSearchInput(e.target.value)
                setPage(0)
              }}
              className="pl-8"
              aria-label="Search users by username or email"
            />
          </div>
          <Select
            value={roleFilter}
            onValueChange={(value) => {
              setRoleFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-full sm:w-[140px]" aria-label="Filter by role">
              <SelectValue placeholder="All roles" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All roles</SelectItem>
              <SelectItem value="admin">Admins</SelectItem>
              <SelectItem value="user">Users</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={statusFilter}
            onValueChange={(value) => {
              setStatusFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-full sm:w-[160px]" aria-label="Filter by status">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="sanctioned">
                <span className="flex items-center gap-1.5">
                  <Ban className="h-3.5 w-3.5 text-destructive" />
                  Sanctioned
                </span>
              </SelectItem>
              <SelectItem value="active">Active only</SelectItem>
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
                <SortableHeader label="Username" column="username" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Email" column="email" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Role" column="role" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Rules" column="rules" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Alerts" column="alerts" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Webhooks" column="webhooks" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
                <SortableHeader label="Joined" column="created_at" sortBy={sortBy} sortDir={sortDir} onSort={toggleSort} />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(!usersData || usersData.length === 0) && !usersLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    {debouncedSearch || roleFilter !== 'all'
                      ? 'No users match your filters'
                      : 'No users found'}
                  </TableCell>
                </TableRow>
              ) : null}

              {usersData?.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium max-w-[200px]">
                    <button
                      type="button"
                      className="hover:underline text-left cursor-pointer text-primary flex items-center gap-2 min-w-0"
                      onClick={() => onOpenUserDetail(user.id)}
                    >
                      <UserAvatar src={user.avatar_url} alt="" size={28} />
                      <span className="truncate">{user.username}</span>
                    </button>
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate">{user.email}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {user.is_super_admin ? (
                        <Badge variant="default" className="gap-1 !border-transparent !bg-gradient-to-r !from-purple-600 !to-pink-600 !text-white">
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
                  <TableCell>{formatDateOnly(user.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t">
            <p className="text-sm text-muted-foreground">
              Showing {page * ADMIN_USERS_PAGE_SIZE + 1}–
              {Math.min((page + 1) * ADMIN_USERS_PAGE_SIZE, totalUsers)} of {totalUsers} users
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft className="h-4 w-4 mr-1" /> Previous
              </Button>
              <span className="text-sm font-medium px-2">
                {page + 1} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Next <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
