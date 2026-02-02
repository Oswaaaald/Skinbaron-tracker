'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { extractErrorMessage } from '@/lib/utils'
import { QUERY_KEYS } from '@/lib/constants'
import { validateUsername, validateEmail, validatePasswordChange } from '@/lib/validation'
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
import { AlertCircle, CheckCircle, Shield, User, Mail, Lock, Trash2, Activity, ShieldCheck } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { TwoFactorSetup } from '@/components/two-factor-setup'
import { SecurityHistory } from '@/components/security-history'
import { useFormState } from '@/hooks/use-form-state'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'

interface UserStats {
  rules_count: number
  alerts_count: number
  webhooks_count: number
}

export function ProfileSettings() {
  const { user, logout, updateUser } = useAuth()
  const { state: formState, setError, setSuccess, clear } = useFormState()
  const { toast } = useToast()
  
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')
  const [twoFactorDialog, setTwoFactorDialog] = useState(false)
  const [disableTwoFactorDialog, setDisableTwoFactorDialog] = useState(false)
  const [twoFactorPassword, setTwoFactorPassword] = useState('')

  // Sync local state with user context when user data changes
  useEffect(() => {
    if (user) {
      setUsername(user.username)
      setEmail(user.email)
    }
  }, [user])

  // Fetch user stats
  const { data: stats, isLoading: isLoadingStats } = useQuery({
    queryKey: [QUERY_KEYS.USER_STATS],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/user/stats'), 'Failed to load user stats')
      return response.data as UserStats
    },
    staleTime: 5_000,
    refetchInterval: 5_000,
    refetchOnWindowFocus: true,
  })

  // Update profile mutation
  const updateProfileMutation = useApiMutation(
    (data: { username?: string; email?: string }) => apiClient.patch('/api/user/profile', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_PROFILE], [QUERY_KEYS.ADMIN_USERS], [QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Profile updated successfully',
      onSuccess: (response) => {
        // Update auth context with data from backend (includes updated avatar_url)
        if (response?.data) {
          const userData = response.data as { 
            id: number; 
            username: string; 
            email: string; 
            avatar_url?: string; 
            is_admin?: boolean; 
          };
          updateUser({
            id: userData.id,
            username: userData.username,
            email: userData.email,
            avatar_url: userData.avatar_url,
            is_admin: userData.is_admin,
          })
        }
        toast({
          title: "✅ Profile updated",
          description: "Your profile has been updated successfully",
        })
        setSuccess('profile', 'Profile updated successfully')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to update profile')
        toast({
          variant: "destructive",
          title: "❌ Update failed",
          description: errorMsg,
        })
        setError('profile', errorMsg)
      },
    }
  )

  // Update password mutation
  const updatePasswordMutation = useApiMutation(
    (data: { current_password: string; new_password: string }) => apiClient.patch('/api/user/password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Password updated successfully',
      onSuccess: () => {
        toast({
          title: "✅ Password changed",
          description: "Your password has been updated successfully",
        })
        setSuccess('password', 'Password updated successfully')
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to update password')
        toast({
          variant: "destructive",
          title: "❌ Password update failed",
          description: errorMsg,
        })
        setError('password', errorMsg)
      },
    }
  )

  // Delete account mutation
  const deleteAccountMutation = useApiMutation(
    () => apiClient.delete('/api/user/account'),
    {
      onSuccess: () => {
        toast({
          title: "✅ Account deleted",
          description: "Your account has been permanently deleted",
        })
        logout()
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to delete account')
        setError('general', errorMsg)
        setDeleteDialog(false)
        setDeleteConfirmText('')
      },
    }
  )

  // 2FA status query
  const { data: twoFactorStatus } = useQuery({
    queryKey: [QUERY_KEYS.TWO_FA_STATUS],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/user/2fa/status'), 'Failed to load 2FA status')
      return response.data as { enabled: boolean }
    },
  })

  // Disable 2FA mutation
  const disableTwoFactorMutation = useApiMutation(
    (password: string) => apiClient.post('/api/user/2fa/disable', { password }),
    {
      invalidateKeys: [[QUERY_KEYS.TWO_FA_STATUS]],
      successMessage: 'Two-factor authentication disabled successfully',
      onSuccess: () => {
        toast({
          title: "✅ 2FA disabled",
          description: "Two-factor authentication has been disabled",
        })
        setSuccess('general', 'Two-factor authentication disabled successfully')
        clear('twoFactor')
        setDisableTwoFactorDialog(false)
        setTwoFactorPassword('')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to disable 2FA')
        toast({
          variant: "destructive",
          title: "❌ Failed to disable 2FA",
          description: errorMsg,
        })
        setError('twoFactor', errorMsg)
      },
    }
  )

  const handleUpdateProfile = (e: React.FormEvent) => {
    e.preventDefault()
    
    // Clear previous messages
    clear('profile')
    
    const updates: { username?: string; email?: string } = {}
    
    if (username !== user?.username) {
      // Validate username
      const result = validateUsername(username)
      if (!result.valid) {
        setError('profile', result.error || 'Invalid username')
        return
      }
      updates.username = username
    }
    
    if (email !== user?.email) {
      // Validate email
      const result = validateEmail(email)
      if (!result.valid) {
        setError('profile', result.error || 'Invalid email')
        return
      }
      updates.email = email
    }
    
    if (Object.keys(updates).length === 0) {
      setError('profile', 'No changes to save')
      return
    }
    
    updateProfileMutation.mutate(updates)
  }

  const handleUpdatePassword = (e: React.FormEvent) => {
    e.preventDefault()
    
    // Clear previous messages
    clear('password')
    
    // Validate password change
    const result = validatePasswordChange({
      currentPassword,
      newPassword,
      confirmPassword,
    })
    
    if (!result.valid) {
      setError('password', result.error || 'Validation failed')
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

  const handleDisable2FA = (e: React.FormEvent) => {
    e.preventDefault()
    if (twoFactorPassword) {
      disableTwoFactorMutation.mutate(twoFactorPassword)
    }
  }

  if (isLoadingStats) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Success/Error Messages */}
      {formState.general.success && (
        <Alert className="border-green-500/50 bg-green-500/10">
          <CheckCircle className="h-4 w-4 text-green-500" />
          <AlertDescription className="text-green-500">{formState.general.success}</AlertDescription>
        </Alert>
      )}
      
      {formState.general.error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{formState.general.error}</AlertDescription>
        </Alert>
      )}

      {/* User Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.rules_count ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
            <AlertCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.alerts_count ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
            <Mail className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.webhooks_count ?? 0}</div>
          </CardContent>
        </Card>
      </div>

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
          {/* Profile update messages */}
          {formState.profile.success && (
            <Alert className="border-green-500/50 bg-green-500/10 mb-4">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <AlertDescription className="text-green-500">{formState.profile.success}</AlertDescription>
            </Alert>
          )}
          
          {formState.profile.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{formState.profile.error}</AlertDescription>
            </Alert>
          )}
          
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
              {user?.is_super_admin ? (
                <Badge variant="default" className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600 text-white">
                  <Shield className="h-3 w-3" />
                  Super Admin
                </Badge>
              ) : user?.is_admin ? (
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
              disabled={updateProfileMutation.isPending}
            >
              {updateProfileMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" inline />
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
          {/* Password change messages */}
          {formState.password.success && (
            <Alert className="border-green-500/50 bg-green-500/10 mb-4">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <AlertDescription className="text-green-500">{formState.password.success}</AlertDescription>
            </Alert>
          )}
          
          {formState.password.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{formState.password.error}</AlertDescription>
            </Alert>
          )}
          
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
              disabled={updatePasswordMutation.isPending}
            >
              {updatePasswordMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" inline />
                  Updating...
                </>
              ) : (
                'Change Password'
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Two-Factor Authentication */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            Two-Factor Authentication
          </CardTitle>
          <CardDescription>Add an extra layer of security to your account</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-medium">Status:</span>
                {twoFactorStatus?.enabled ? (
                  <Badge variant="default" className="gap-1">
                    <Shield className="h-3 w-3" />
                    Enabled
                  </Badge>
                ) : (
                  <Badge variant="outline">Disabled</Badge>
                )}
              </div>
              <p className="text-sm text-muted-foreground">
                {twoFactorStatus?.enabled 
                  ? 'Your account is protected with 2FA' 
                  : 'Use an authenticator app for extra security'}
              </p>
            </div>
            
            {twoFactorStatus?.enabled ? (
              <Button 
                variant="destructive" 
                onClick={() => setDisableTwoFactorDialog(true)}
              >
                Disable 2FA
              </Button>
            ) : (
              <Button onClick={() => setTwoFactorDialog(true)}>
                Enable 2FA
              </Button>
            )}
          </div>

          {twoFactorStatus?.enabled && (
            <Alert>
              <Shield className="h-4 w-4" />
              <AlertDescription>
                You&apos;ll be asked for a verification code when logging in. Keep your authenticator app accessible.
              </AlertDescription>
            </Alert>
          )}
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

      {/* 2FA Setup Dialog */}
      <TwoFactorSetup open={twoFactorDialog} onOpenChange={setTwoFactorDialog} />

      {/* Disable 2FA Dialog */}
      <Dialog open={disableTwoFactorDialog} onOpenChange={setDisableTwoFactorDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication?</DialogTitle>
            <DialogDescription>
              Enter your password to confirm disabling 2FA
            </DialogDescription>
          </DialogHeader>
          
          <form onSubmit={handleDisable2FA}>
            <div className="space-y-4">
              {formState.twoFactor.error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{formState.twoFactor.error}</AlertDescription>
                </Alert>
              )}
              
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Your account will be less secure without 2FA protection.
                </AlertDescription>
              </Alert>
              
              <div className="space-y-2">
                <Label htmlFor="2fa-password">Password</Label>
                <Input
                  id="2fa-password"
                  type="password"
                  value={twoFactorPassword}
                  onChange={(e) => setTwoFactorPassword(e.target.value)}
                  placeholder="Enter your password"
                />
              </div>
            </div>
            
            <DialogFooter className="mt-4">
              <Button 
                type="button"
                variant="outline" 
                onClick={() => {
                  setDisableTwoFactorDialog(false)
                  setTwoFactorPassword('')
                  clear('twoFactor')
                }}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="destructive"
                disabled={!twoFactorPassword || disableTwoFactorMutation.isPending}
              >
                {disableTwoFactorMutation.isPending ? (
                  <>
                    <LoadingSpinner size="sm" inline />
                    <span className="ml-2">Disabling...</span>
                  </>
                ) : (
                  'Disable 2FA'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

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
                  <LoadingSpinner size="sm" inline />
                  <span className="ml-2">Deleting...</span>
                </>
              ) : (
                'Delete My Account'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Security History - Non-intrusive placement at bottom */}
      <SecurityHistory />
    </div>
  )
}
