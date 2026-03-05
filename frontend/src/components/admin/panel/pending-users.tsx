'use client'

import { AlertCircle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateOnly } from '@/lib/formatters'

export interface PendingUser {
  id: number
  username: string
  email: string
  created_at: string
}

interface PendingUserDialogState {
  open: boolean
  userId: number | null
  action: 'approve' | 'reject'
}

interface AdminPanelPendingUsersProps {
  pendingUsers: PendingUser[]
  pendingUserDialog: PendingUserDialogState
  setPendingUserDialog: (state: PendingUserDialogState) => void
  approvePending: boolean
  rejectPending: boolean
}

export function AdminPanelPendingUsers({
  pendingUsers,
  pendingUserDialog,
  setPendingUserDialog,
  approvePending,
  rejectPending,
}: AdminPanelPendingUsersProps) {
  if (!pendingUsers.length) return null

  return (
    <Card className="border-orange-500 border-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertCircle className="h-5 w-5 text-orange-500" />
          Pending Approvals ({pendingUsers.length})
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
            {pendingUsers.map((user) => (
              <TableRow key={user.id}>
                <TableCell className="font-medium max-w-[160px] truncate">{user.username}</TableCell>
                <TableCell className="max-w-[200px] truncate">{user.email}</TableCell>
                <TableCell>{formatDateOnly(user.created_at)}</TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() =>
                        setPendingUserDialog({
                          open: true,
                          userId: user.id,
                          action: 'approve',
                        })
                      }
                      disabled={approvePending || pendingUserDialog.open}
                    >
                      Approve
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() =>
                        setPendingUserDialog({
                          open: true,
                          userId: user.id,
                          action: 'reject',
                        })
                      }
                      disabled={rejectPending || pendingUserDialog.open}
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
  )
}
