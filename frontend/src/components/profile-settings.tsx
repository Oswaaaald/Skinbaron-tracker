'use client'

import { useState, useEffect, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { extractErrorMessage } from '@/lib/utils'
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from '@/lib/constants'
import { validateUsername, validateEmail, validatePasswordChange, validateSetPassword } from '@/lib/validation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingState } from '@/components/ui/loading-state'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { AlertCircle, CheckCircle, Shield, User, Mail, Lock, Trash2, Activity, ShieldCheck, Download } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { usePageVisible } from '@/hooks/use-page-visible'
import { TwoFactorSetup } from '@/components/two-factor-setup'
import { SecurityHistory } from '@/components/security-history'
import { useFormState } from '@/hooks/use-form-state'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

interface UserStats {
  rules_count: number
  alerts_count: number
  webhooks_count: number
}

export function ProfileSettings() {
  const { user, logout, updateUser, isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()
  const { state: formState, setError, setSuccess, clear } = useFormState()
  const { toast } = useToast()
  
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')
  const [deletePassword, setDeletePassword] = useState('')
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
    enabled: isReady && isAuthenticated,
    staleTime: SLOW_POLL_INTERVAL,
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
  })

  // Fetch linked OAuth accounts (for email picker)
  const { data: oauthAccounts } = useQuery({
    queryKey: ['oauth-accounts'],
    queryFn: async () => {
      const res = await apiClient.getOAuthAccounts()
      return res.success ? (res.data ?? []) : []
    },
    enabled: isReady && isAuthenticated,
    staleTime: 30_000,
  })

  // Build list of available emails for non-admin users
  const availableEmails = (() => {
    if (user?.is_admin) return [] // admins use free-text input
    const emails = new Set<string>()
    if (user?.email) emails.add(user.email)
    for (const a of oauthAccounts ?? []) {
      if (a.provider_email) emails.add(a.provider_email)
    }
    return [...emails]
  })()

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
        setSuccess('profile', 'Profile updated successfully')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to update profile')
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
        setSuccess('password', 'Password updated successfully')
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to update password')
        setError('password', errorMsg)
      },
    }
  )

  // Set password mutation (for OAuth-only users)
  const setPasswordMutation = useApiMutation(
    (data: { new_password: string }) => apiClient.post('/api/user/set-password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS], [QUERY_KEYS.USER_PROFILE]],
      successMessage: 'Password set successfully',
      onSuccess: () => {
        setSuccess('password', 'Password set successfully! You can now use it to log in.')
        setNewPassword('')
        setConfirmPassword('')
        // Update local user to reflect has_password
        if (user) updateUser({ ...user, has_password: true })
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to set password')
        setError('password', errorMsg)
      },
    }
  )

  // Delete account mutation
  const deleteAccountMutation = useApiMutation(
    (data: { password?: string; totp_code?: string }) => apiClient.delete('/api/user/account', data),
    {
      onSuccess: () => {
        toast({
          title: "✅ Account deleted",
          description: "Your account has been permanently deleted",
        })
        void logout()
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
    enabled: isReady && isAuthenticated,
  })

  // Disable 2FA mutation
  const disableTwoFactorMutation = useApiMutation(
    (data?: { password?: string; totp_code?: string }) => apiClient.post('/api/user/2fa/disable', data ?? {}),
    {
      invalidateKeys: [[QUERY_KEYS.TWO_FA_STATUS]],
      successMessage: 'Two-factor authentication disabled successfully',
      onSuccess: () => {
        setSuccess('general', 'Two-factor authentication disabled successfully')
        clear('twoFactor')
        setDisableTwoFactorDialog(false)
        setTwoFactorPassword('')
      },
      onError: (error: unknown) => {
        const errorMsg = extractErrorMessage(error, 'Failed to disable 2FA')
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
    
    if (!user?.has_password) {
      // Set password flow for OAuth-only users
      const result = validateSetPassword({
        newPassword,
        confirmPassword,
      })
      
      if (!result.valid) {
        setError('password', result.error || 'Validation failed')
        return
      }
      
      setPasswordMutation.mutate({
        new_password: newPassword,
      })
    } else {
      // Change password flow for users with existing password
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
  }

  const handleDeleteAccount = () => {
    if (deleteConfirmText === user?.username) {
      if (user?.has_password) {
        if (deletePassword) deleteAccountMutation.mutate({ password: deletePassword })
      } else if (twoFactorStatus?.enabled) {
        // OAuth-only users with 2FA enabled: require TOTP code
        if (deletePassword) deleteAccountMutation.mutate({ totp_code: deletePassword })
      } else {
        deleteAccountMutation.mutate({})
      }
    }
  }

  const handleDisable2FA = (e: React.FormEvent) => {
    e.preventDefault()
    if (user?.has_password) {
      if (twoFactorPassword) disableTwoFactorMutation.mutate({ password: twoFactorPassword })
    } else {
      // OAuth-only users need to provide a TOTP code
      if (twoFactorPassword) disableTwoFactorMutation.mutate({ totp_code: twoFactorPassword })
    }
  }

  if (isLoadingStats) {
    return <LoadingState variant="card" />
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
            {isLoadingStats && !stats ? (
              <LoadingSpinner size="sm" />
            ) : (
              <div className="text-2xl font-bold">{stats?.rules_count ?? 0}</div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
            <AlertCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoadingStats && !stats ? (
              <LoadingSpinner size="sm" />
            ) : (
              <div className="text-2xl font-bold">{stats?.alerts_count ?? 0}</div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
            <Mail className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoadingStats && !stats ? (
              <LoadingSpinner size="sm" />
            ) : (
              <div className="text-2xl font-bold">{stats?.webhooks_count ?? 0}</div>
            )}
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
              {user?.is_admin ? (
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter email"
                />
              ) : availableEmails.length > 1 ? (
                <>
                  <Select value={email} onValueChange={setEmail}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="Select email" />
                    </SelectTrigger>
                    <SelectContent>
                      {availableEmails.map(e => (
                        <SelectItem key={e} value={e}>{e}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground">
                    You can choose from your linked OAuth provider emails
                  </p>
                </>
              ) : (
                <>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    disabled
                  />
                  <p className="text-sm text-muted-foreground">
                    Link an OAuth account with a different email to change it
                  </p>
                </>
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

      {/* Change Password / Set Password */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            {user?.has_password ? 'Change Password' : 'Set Password'}
          </CardTitle>
          <CardDescription>
            {user?.has_password
              ? 'Update your password to keep your account secure'
              : 'Set a password to enable email/password login alongside your social accounts'}
          </CardDescription>
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
            {user?.has_password && (
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
            )}
            
            <div className="space-y-2">
              <Label htmlFor="new-password">{user?.has_password ? 'New Password' : 'Password'}</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password (min 8 characters)"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
              />
            </div>
            
            <Button 
              type="submit" 
              disabled={updatePasswordMutation.isPending || setPasswordMutation.isPending}
            >
              {(updatePasswordMutation.isPending || setPasswordMutation.isPending) ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" inline />
                  {user?.has_password ? 'Updating...' : 'Setting...'}
                </>
              ) : (
                user?.has_password ? 'Change Password' : 'Set Password'
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

      {/* Data Export (GDPR Art. 20) */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Your Data
          </CardTitle>
          <CardDescription>Download or delete all your personal data (GDPR)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Export all your data (profile, rules, webhooks, alerts, audit logs) as a JSON file.
          </p>
          <Button
            variant="outline"
            onClick={() => {
              void (async () => {
              try {
                const response = await apiClient.get('/api/user/data-export')
                if (response.success && response.data) {
                  const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `skinbaron-tracker-export-${new Date().toISOString().split('T')[0]}.json`
                  document.body.appendChild(a)
                  a.click()
                  document.body.removeChild(a)
                  // Delay revoke to ensure browser picks up the blob
                  setTimeout(() => URL.revokeObjectURL(url), 1000)
                  toast({ title: '✅ Data exported', description: 'Your data has been downloaded' })
                }
              } catch (error) {
                toast({ variant: 'destructive', title: '❌ Export failed', description: extractErrorMessage(error, 'Failed to export data') })
              }
            })()
            }}
          >
            <Download className="h-4 w-4 mr-2" />
            Export My Data
          </Button>
        </CardContent>
      </Card>

      {/* Linked OAuth Accounts */}
      <LinkedAccounts />

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
              {user?.has_password
                ? 'Enter your password to confirm disabling 2FA'
                : 'Enter a 2FA code from your authenticator app to confirm'}
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
                <Label htmlFor="2fa-password">
                  {user?.has_password ? 'Password' : '2FA Code'}
                </Label>
                <Input
                  id="2fa-password"
                  type={user?.has_password ? 'password' : 'text'}
                  inputMode={user?.has_password ? undefined : 'numeric'}
                  maxLength={user?.has_password ? undefined : 8}
                  value={twoFactorPassword}
                  onChange={(e) => setTwoFactorPassword(e.target.value)}
                  placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'}
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
            
            {(user?.has_password || twoFactorStatus?.enabled) && (
              <div className="space-y-2">
                <Label htmlFor="delete-password">
                  {user?.has_password ? 'Enter your password' : 'Enter your 2FA code'}
                </Label>
                <Input
                  id="delete-password"
                  type={user?.has_password ? 'password' : 'text'}
                  inputMode={user?.has_password ? undefined : 'numeric'}
                  maxLength={user?.has_password ? undefined : 8}
                  value={deletePassword}
                  onChange={(e) => setDeletePassword(e.target.value)}
                  placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'}
                />
              </div>
            )}
          </div>
          
          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => {
                setDeleteDialog(false)
                setDeleteConfirmText('')
                setDeletePassword('')
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteAccount}
              disabled={deleteConfirmText !== user?.username || ((user?.has_password || twoFactorStatus?.enabled) && !deletePassword) || deleteAccountMutation.isPending}
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

// ==================== Linked OAuth Accounts ====================

const PROVIDER_META: Record<string, { label: string; icon: ReactNode }> = {
  google: {
    label: 'Google',
    icon: <svg className="h-4 w-4" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>,
  },
  github: {
    label: 'GitHub',
    icon: <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>,
  },
  discord: {
    label: 'Discord',
    icon: <svg className="h-4 w-4" viewBox="0 0 24 24" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>,
  },
}

const LINK_ERROR_MESSAGES: Record<string, string> = {
  already_linked_other: 'This social account is already linked to another user.',
  account_not_found: 'Your account was not found. Please log in again.',
  server_error: 'An unexpected error occurred. Please try again.',
}

function LinkedAccounts() {
  const { toast } = useToast()
  const [unlinking, setUnlinking] = useState<string | null>(null)
  const [confirmUnlink, setConfirmUnlink] = useState<string | null>(null)

  // Handle ?linked= and ?link_error= query params from OAuth redirect
  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    const linked = params.get('linked')
    const linkError = params.get('link_error')

    if (linked) {
      const label = PROVIDER_META[linked]?.label ?? linked
      toast({ title: '✅ Account linked', description: `${label} account has been linked successfully.` })
    }
    if (linkError) {
      toast({ variant: 'destructive', title: '❌ Link failed', description: LINK_ERROR_MESSAGES[linkError] || 'Could not link account. Please try again.' })
    }

    // Clean the URL
    if (linked || linkError) {
      const url = new URL(window.location.href)
      url.searchParams.delete('linked')
      url.searchParams.delete('link_error')
      window.history.replaceState({}, '', url.pathname + url.search)
    }
  }, [toast])

  // Fetch enabled providers
  const { data: enabledProviders } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: async () => {
      const res = await apiClient.getOAuthProviders()
      return res.success ? (res.data?.providers ?? []) : []
    },
    staleTime: 5 * 60 * 1000,
  })

  // Fetch linked accounts
  const { data: accounts, refetch } = useQuery({
    queryKey: ['oauth-accounts'],
    queryFn: async () => {
      const res = await apiClient.getOAuthAccounts()
      return res.success ? (res.data ?? []) : []
    },
    staleTime: 30_000,
  })

  const handleUnlink = async (provider: string) => {
    setUnlinking(provider)
    try {
      const res = await apiClient.unlinkOAuthAccount(provider)
      if (res.success) {
        toast({ title: '✅ Account unlinked', description: `${PROVIDER_META[provider]?.label ?? provider} account has been unlinked.` })
        void refetch()
      } else {
        toast({ variant: 'destructive', title: '❌ Failed', description: res.message || 'Could not unlink account.' })
      }
    } catch (err) {
      toast({ variant: 'destructive', title: '❌ Error', description: extractErrorMessage(err, 'Could not unlink account.') })
    } finally {
      setUnlinking(null)
    }
  }

  const handleLink = (provider: string) => {
    window.location.href = apiClient.getOAuthLoginUrl(provider)
  }

  // Don't render if no providers are enabled
  if (!enabledProviders || enabledProviders.length === 0) return null

  const linkedProviders = new Set((accounts ?? []).map(a => a.provider))

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Linked Accounts
        </CardTitle>
        <CardDescription>Manage your social login connections</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {enabledProviders.map(provider => {
          const meta = PROVIDER_META[provider] ?? { label: provider, icon: null }
          const isLinked = linkedProviders.has(provider)
          const account = (accounts ?? []).find(a => a.provider === provider)

          return (
            <div key={provider} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex items-center gap-3">
                {meta.icon}
                <div>
                  <p className="text-sm font-medium">{meta.label}</p>
                  {isLinked && account?.provider_email && (
                    <p className="text-xs text-muted-foreground">{account.provider_email}</p>
                  )}
                </div>
              </div>
              {isLinked ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={unlinking === provider}
                  onClick={() => setConfirmUnlink(provider)}
                >
                  {unlinking === provider ? <LoadingSpinner size="sm" inline /> : 'Unlink'}
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={() => handleLink(provider)}>
                  Link
                </Button>
              )}
            </div>
          )
        })}
      </CardContent>

      <ConfirmDialog
        open={!!confirmUnlink}
        onOpenChange={(open) => { if (!open) setConfirmUnlink(null) }}
        title="Unlink account?"
        description={`Are you sure you want to unlink your ${PROVIDER_META[confirmUnlink ?? '']?.label ?? confirmUnlink} account? You can always re-link it later.`}
        confirmText="Unlink"
        variant="destructive"
        onConfirm={() => { if (confirmUnlink) void handleUnlink(confirmUnlink) }}
      />
    </Card>
  )
}
