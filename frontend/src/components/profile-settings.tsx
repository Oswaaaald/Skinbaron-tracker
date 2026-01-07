'use client'

import { useState, useEffect } from 'react'
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { AlertCircle, CheckCircle, Shield, User, Mail, Lock, Trash2, Activity } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'

interface UserStats {
  rules_count: number
  alerts_count: number
  webhooks_count: number
}

export function ProfileSettings() {
  const { user, logout, updateUser } = useAuth()
  const queryClient = useQueryClient()
  
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')
  
  const [successMessage, setSuccessMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')

  // Sync local state with user context when user data changes
  useEffect(() => {
    if (user) {
      setUsername(user.username)
      setEmail(user.email)
    }
  }, [user])

  // Fetch user stats
  const { data: stats } = useQuery({
    queryKey: ['user', 'stats'],
    queryFn: async () => {
      const response = await apiClient.get('/api/user/stats')
      return response.data as UserStats
    },
  })

  // Update profile mutation
  const updateProfileMutation = useMutation({
    mutationFn: async (data: { username?: string; email?: string }) => {
      return await apiClient.patch('/api/user/profile', data)
    },
    onSuccess: (response) => {
      setSuccessMessage('Profile updated successfully')
      setErrorMessage('')
      queryClient.invalidateQueries({ queryKey: ['user', 'profile'] })
      // Also invalidate admin queries so admin panel updates
      queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      // Update auth context with data from backend (includes updated avatar_url)
      if (response?.data) {
        const userData = response.data
        updateUser({
          id: userData.id,
          username: userData.username,
          email: userData.email,
          avatar_url: userData.avatar_url,
          is_admin: userData.is_admin,
        })
      }
    },
    onError: (error: any) => {
      setErrorMessage(error.message || 'Failed to update profile')
      setSuccessMessage('')
    },
  })

  // Update password mutation
  const updatePasswordMutation = useMutation({
    mutationFn: async (data: { current_password: string; new_password: string }) => {
      return await apiClient.patch('/api/user/password', data)
    },
    onSuccess: () => {
      setSuccessMessage('Password updated successfully')
      setErrorMessage('')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    },
    onError: (error: any) => {
      setErrorMessage(error.message || 'Failed to update password')
      setSuccessMessage('')
    },
  })

  // Delete account mutation
  const deleteAccountMutation = useMutation({
    mutationFn: async () => {
      return await apiClient.delete('/api/user/account')
    },
    onSuccess: () => {
      logout()
    },
    onError: (error: any) => {
      setErrorMessage(error.message || 'Failed to delete account')
      setDeleteDialog(false)
      setDeleteConfirmText('')
    },
  })

  const handleUpdateProfile = (e: React.FormEvent) => {
    e.preventDefault()
    const updates: { username?: string; email?: string } = {}
    
    if (username !== user?.username) updates.username = username
    if (email !== user?.email) updates.email = email
    
    if (Object.keys(updates).length > 0) {
      updateProfileMutation.mutate(updates)
    }
  }

  const handleUpdatePassword = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (newPassword !== confirmPassword) {
      setErrorMessage('Passwords do not match')
      return
    }
    
    if (newPassword.length < 8) {
      setErrorMessage('Password must be at least 8 characters')
      return
    }
    
    updatePasswordMutation.mutate({
      current_password: currentPassword,
      new_password: newPassword,
    })
  }

  const handleDeleteAccount = () => {
    if (deleteConfirmText === user?.username) {
      deleteAccountMutation.mutate()
    }
  }

  return (
    <div className="space-y-6">
      {/* Success/Error Messages */}
      {successMessage && (
        <Alert className="border-green-500/50 bg-green-500/10">
          <CheckCircle className="h-4 w-4 text-green-500" />
          <AlertDescription className="text-green-500">{successMessage}</AlertDescription>
        </Alert>
      )}
      
      {errorMessage && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      )}

      {/* User Stats */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.rules_count}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
              <AlertCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.alerts_count}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
              <Mail className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.webhooks_count}</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Profile Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile Information
          </CardTitle>
          <CardDescription>Update your account details</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleUpdateProfile} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email"
                disabled={!user?.is_admin}
              />
              {!user?.is_admin && (
                <p className="text-sm text-muted-foreground">
                  Only administrators can change their email address
                </p>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Label>Role:</Label>
              {user?.is_admin ? (
                <Badge variant="default" className="gap-1">
                  <Shield className="h-3 w-3" />
                  Admin
                </Badge>
              ) : (
                <Badge variant="outline">User</Badge>
              )}
            </div>
            
            <Button 
              type="submit" 
              disabled={updateProfileMutation.isPending || (username === user?.username && email === user?.email)}
            >
              {updateProfileMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Updating...
                </>
              ) : (
                'Update Profile'
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Change Password */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            Change Password
          </CardTitle>
          <CardDescription>Update your password to keep your account secure</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleUpdatePassword} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="current-password">Current Password</Label>
              <Input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="new-password">New Password</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password (min 8 characters)"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm New Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
              />
            </div>
            
            <Button 
              type="submit" 
              disabled={updatePasswordMutation.isPending || !currentPassword || !newPassword || !confirmPassword}
            >
              {updatePasswordMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Updating...
                </>
              ) : (
                'Change Password'
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Danger Zone */}
      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" />
            Danger Zone
          </CardTitle>
          <CardDescription>Permanently delete your account and all associated data</CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive" className="mb-4">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              This action cannot be undone. All your rules, alerts, and webhooks will be permanently deleted.
            </AlertDescription>
          </Alert>
          
          <Button 
            variant="destructive" 
            onClick={() => setDeleteDialog(true)}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete Account
          </Button>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Are you absolutely sure?</DialogTitle>
            <DialogDescription>
              This will permanently delete your account and all associated data. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Warning:</strong> You will lose access to:
                <ul className="list-disc list-inside mt-2">
                  <li>{stats?.rules_count || 0} active rules</li>
                  <li>{stats?.alerts_count || 0} alert history</li>
                  <li>{stats?.webhooks_count || 0} webhook configurations</li>
                </ul>
              </AlertDescription>
            </Alert>
            
            <div className="space-y-2">
              <Label>Type your username to confirm: <strong>{user?.username}</strong></Label>
              <Input
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder={user?.username}
              />
            </div>
          </div>
          
          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => {
                setDeleteDialog(false)
                setDeleteConfirmText('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteAccount}
              disabled={deleteConfirmText !== user?.username || deleteAccountMutation.isPending}
            >
              {deleteAccountMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Deleting...
                </>
              ) : (
                'Delete My Account'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
