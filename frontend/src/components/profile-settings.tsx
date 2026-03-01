'use client'

import { useState, useEffect, useRef, useMemo } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { extractErrorMessage } from '@/lib/utils'
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from '@/lib/constants'
import { PROVIDER_META } from '@/lib/oauth-icons'
import { validateUsername, validateEmail, validatePasswordChange, validateSetPassword } from '@/lib/validation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ProfileSkeleton, LinkedAccountsSkeleton } from '@/components/ui/skeletons'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { AlertCircle, CheckCircle, Shield, User, Mail, Lock, Trash2, Activity, ShieldCheck, Download, Fingerprint, Link2, History, Upload, Camera, X } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { usePageVisible } from '@/hooks/use-page-visible'
import { TwoFactorSetup } from '@/components/two-factor-setup'
import { SecurityHistory } from '@/components/security-history'
import { PasskeyManager } from '@/components/settings-passkeys'
import { SessionManager } from '@/components/session-manager'
import { useFormState } from '@/hooks/use-form-state'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import Image from 'next/image'

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
  const queryClient = useQueryClient()
  
  const [username, setUsername] = useState(user?.username || '')
  const [email, setEmail] = useState(user?.email || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteError, setDeleteError] = useState('')
  const [twoFactorDialog, setTwoFactorDialog] = useState(false)
  const [disableTwoFactorDialog, setDisableTwoFactorDialog] = useState(false)
  const [twoFactorPassword, setTwoFactorPassword] = useState('')
  const [exportDialog, setExportDialog] = useState(false)

  // Avatar state
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [avatarUploading, setAvatarUploading] = useState(false)
  const [avatarDeleting, setAvatarDeleting] = useState(false)
  const [gravatarToggling, setGravatarToggling] = useState(false)
  const [confirmAvatarDelete, setConfirmAvatarDelete] = useState(false)

  // Tab state — default to 'oauth' when returning from OAuth link flow
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window === 'undefined') return 'profile'
    const params = new URLSearchParams(window.location.search)
    return (params.has('linked') || params.has('link_error')) ? 'oauth' : 'profile'
  })

  // Show toast for OAuth link result on first mount (runs in parent so it fires immediately)
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
      const errorMessages: Record<string, string> = {
        already_linked_other: 'This social account is already linked to another user.',
        account_not_found: 'Your account was not found. Please log in again.',
        rate_limited: 'Too many attempts. Please try again in a moment.',
        server_error: 'An unexpected error occurred. Please try again.',
      }
      toast({ variant: 'destructive', title: '❌ Link failed', description: errorMessages[linkError] || 'Could not link account.' })
    }
    if (linked || linkError) {
      const url = new URL(window.location.href)
      url.searchParams.delete('linked')
      url.searchParams.delete('link_error')
      window.history.replaceState({}, '', url.pathname + url.search)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (user) {
      setUsername(user.username)
      setEmail(user.email)
    }
  }, [user])

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

  const { data: oauthAccounts } = useQuery({
    queryKey: ['oauth-accounts'],
    queryFn: async () => {
      const res = await apiClient.getOAuthAccounts()
      return res.success ? (res.data ?? []) : []
    },
    enabled: isReady && isAuthenticated,
    staleTime: 30_000,
  })

  const availableEmails = useMemo(() => {
    if (user?.is_admin) return []
    const emails = new Set<string>()
    if (user?.email) emails.add(user.email)
    for (const a of oauthAccounts ?? []) {
      if (a.provider_email) emails.add(a.provider_email)
    }
    return [...emails]
  }, [user?.is_admin, user?.email, oauthAccounts])

  const updateProfileMutation = useApiMutation(
    (data: { username?: string; email?: string }) => apiClient.patch('/api/user/profile', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_PROFILE], [QUERY_KEYS.ADMIN_USERS], [QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Profile updated successfully',
      onSuccess: (response) => {
        if (response?.data) {
          const userData = response.data as { id: number; username: string; email: string; avatar_url?: string; use_gravatar?: boolean; is_admin?: boolean }
          updateUser({ id: userData.id, username: userData.username, email: userData.email, avatar_url: userData.avatar_url, use_gravatar: userData.use_gravatar, is_admin: userData.is_admin })
        }
        setSuccess('profile', 'Profile updated successfully')
      },
      onError: (error: unknown) => setError('profile', extractErrorMessage(error, 'Failed to update profile')),
    }
  )

  const updatePasswordMutation = useApiMutation(
    (data: { current_password: string; new_password: string }) => apiClient.patch('/api/user/password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Password updated successfully',
      onSuccess: () => { setSuccess('password', 'Password updated successfully'); setCurrentPassword(''); setNewPassword(''); setConfirmPassword('') },
      onError: (error: unknown) => setError('password', extractErrorMessage(error, 'Failed to update password')),
    }
  )

  const setPasswordMutation = useApiMutation(
    (data: { new_password: string }) => apiClient.post('/api/user/set-password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS], [QUERY_KEYS.USER_PROFILE]],
      successMessage: 'Password set successfully',
      onSuccess: () => { setSuccess('password', 'Password set successfully! You can now use it to log in.'); setNewPassword(''); setConfirmPassword(''); if (user) updateUser({ ...user, has_password: true }) },
      onError: (error: unknown) => setError('password', extractErrorMessage(error, 'Failed to set password')),
    }
  )

  const deleteAccountMutation = useApiMutation(
    (data: { password?: string; totp_code?: string }) => apiClient.delete('/api/user/account', data),
    {
      onSuccess: () => { toast({ title: '✅ Account deleted', description: 'Your account has been permanently deleted' }); void logout() },
      onError: (error: unknown) => { setDeleteError(extractErrorMessage(error, 'Failed to delete account')); setDeletePassword('') },
    }
  )

  const { data: twoFactorStatus } = useQuery({
    queryKey: [QUERY_KEYS.TWO_FA_STATUS],
    queryFn: async () => {
      const response = apiClient.ensureSuccess(await apiClient.get('/api/user/2fa/status'), 'Failed to load 2FA status')
      return response.data as { enabled: boolean }
    },
    enabled: isReady && isAuthenticated,
  })

  const disableTwoFactorMutation = useApiMutation(
    (data?: { password?: string; totp_code?: string }) => apiClient.post('/api/user/2fa/disable', data ?? {}),
    {
      invalidateKeys: [[QUERY_KEYS.TWO_FA_STATUS]],
      successMessage: 'Two-factor authentication disabled successfully',
      onSuccess: () => { setSuccess('general', 'Two-factor authentication disabled successfully'); clear('twoFactor'); setDisableTwoFactorDialog(false); setTwoFactorPassword('') },
      onError: (error: unknown) => setError('twoFactor', extractErrorMessage(error, 'Failed to disable 2FA')),
    }
  )

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    // Reset input so the same file can be re-selected
    e.target.value = ''

    // Client-side validation
    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif']
    if (!allowedTypes.includes(file.type)) {
      toast({ title: '❌ Invalid file type', description: 'Please upload a PNG, JPEG, WebP, or GIF image', variant: 'destructive' })
      return
    }
    if (file.size > 5 * 1024 * 1024) {
      toast({ title: '❌ File too large', description: 'Maximum file size is 5 MB', variant: 'destructive' })
      return
    }

    setAvatarUploading(true)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const response = await apiClient.uploadFile<{ avatar_url: string }>('/api/user/avatar', formData)
      if (response.success && response.data) {
        updateUser({ avatar_url: response.data.avatar_url })
        toast({ title: '✅ Avatar updated', description: 'Your avatar has been uploaded successfully' })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Upload failed', description: response.message || 'Failed to upload avatar', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Upload failed', description: extractErrorMessage(error, 'Failed to upload avatar'), variant: 'destructive' })
    } finally {
      setAvatarUploading(false)
    }
  }

  const handleAvatarDelete = async () => {
    setAvatarDeleting(true)
    try {
      const response = await apiClient.delete<{ avatar_url: string | null }>('/api/user/avatar')
      if (response.success) {
        updateUser({ avatar_url: response.data?.avatar_url ?? undefined })
        toast({ title: '✅ Avatar removed', description: 'Your custom avatar has been removed' })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Remove failed', description: response.message || 'Failed to remove avatar', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Remove failed', description: extractErrorMessage(error, 'Failed to remove avatar'), variant: 'destructive' })
    } finally {
      setAvatarDeleting(false)
    }
  }

  const handleGravatarToggle = async (checked: boolean) => {
    setGravatarToggling(true)
    try {
      const response = await apiClient.patch<{ use_gravatar: boolean; avatar_url: string | null }>('/api/user/avatar-settings', { use_gravatar: checked })
      if (response.success && response.data) {
        updateUser({ use_gravatar: response.data.use_gravatar, avatar_url: response.data.avatar_url ?? undefined })
        toast({ title: checked ? '✅ Gravatar enabled' : '✅ Gravatar disabled', description: checked ? 'Your Gravatar will be used as fallback' : 'Gravatar fallback has been disabled' })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Update failed', description: response.message || 'Failed to update setting', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Update failed', description: extractErrorMessage(error, 'Failed to update avatar settings'), variant: 'destructive' })
    } finally {
      setGravatarToggling(false)
    }
  }

  const handleUpdateProfile = (e: React.FormEvent) => {
    e.preventDefault(); clear('profile')
    const updates: { username?: string; email?: string } = {}
    if (username !== user?.username) {
      const result = validateUsername(username)
      if (!result.valid) { setError('profile', result.error || 'Invalid username'); return }
      updates.username = username
    }
    if (email !== user?.email) {
      const result = validateEmail(email)
      if (!result.valid) { setError('profile', result.error || 'Invalid email'); return }
      updates.email = email
    }
    if (Object.keys(updates).length === 0) { setError('profile', 'No changes to save'); return }
    updateProfileMutation.mutate(updates)
  }

  const handleUpdatePassword = (e: React.FormEvent) => {
    e.preventDefault(); clear('password')
    if (!user?.has_password) {
      const result = validateSetPassword({ newPassword, confirmPassword })
      if (!result.valid) { setError('password', result.error || 'Validation failed'); return }
      setPasswordMutation.mutate({ new_password: newPassword })
    } else {
      const result = validatePasswordChange({ currentPassword, newPassword, confirmPassword })
      if (!result.valid) { setError('password', result.error || 'Validation failed'); return }
      updatePasswordMutation.mutate({ current_password: currentPassword, new_password: newPassword })
    }
  }

  const handleDeleteAccount = () => {
    if (deleteConfirmText !== user?.username) return
    if (user?.has_password) { if (deletePassword) deleteAccountMutation.mutate({ password: deletePassword }) }
    else if (twoFactorStatus?.enabled) { if (deletePassword) deleteAccountMutation.mutate({ totp_code: deletePassword }) }
    else { deleteAccountMutation.mutate({}) }
  }

  const handleDisable2FA = (e: React.FormEvent) => {
    e.preventDefault()
    if (user?.has_password) { if (twoFactorPassword) disableTwoFactorMutation.mutate({ password: twoFactorPassword }) }
    else { if (twoFactorPassword) disableTwoFactorMutation.mutate({ totp_code: twoFactorPassword }) }
  }

  if (isLoadingStats) return <ProfileSkeleton />

  return (
    <div className="space-y-6">
      {formState.general.success && (
        <Alert className="border-primary/50 bg-primary/10"><CheckCircle className="h-4 w-4 text-primary" /><AlertDescription className="text-primary">{formState.general.success}</AlertDescription></Alert>
      )}
      {formState.general.error && (
        <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{formState.general.error}</AlertDescription></Alert>
      )}

      {/* User Stats */}
      <div className="grid gap-4 md:grid-cols-3 animate-stagger">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{stats?.rules_count ?? 0}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts</CardTitle>
            <AlertCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{stats?.alerts_count ?? 0}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Webhooks</CardTitle>
            <Mail className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent><div className="text-2xl font-bold">{stats?.webhooks_count ?? 0}</div></CardContent>
        </Card>
      </div>

      {/* Tabbed Settings */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="w-full flex">
          <TabsTrigger value="profile" className="flex items-center gap-1.5"><User className="h-4 w-4" /><span className="hidden sm:inline">Profile</span></TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-1.5"><Shield className="h-4 w-4" /><span className="hidden sm:inline">Security</span></TabsTrigger>
          <TabsTrigger value="oauth" className="flex items-center gap-1.5"><Link2 className="h-4 w-4" /><span className="hidden sm:inline">Accounts</span></TabsTrigger>
          <TabsTrigger value="logs" className="flex items-center gap-1.5"><History className="h-4 w-4" /><span className="hidden sm:inline">Logs</span></TabsTrigger>
        </TabsList>

        {/* ===================== Profile Tab ===================== */}
        <TabsContent value="profile" className="space-y-4 mt-4">
          {/* Avatar */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Camera className="h-5 w-5" /> Avatar</CardTitle>
              <CardDescription>Upload a custom avatar or use your Gravatar</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-6">
                {/* Preview */}
                <div className="relative group shrink-0">
                  <div className="h-20 w-20 rounded-full overflow-hidden ring-2 ring-border bg-muted flex items-center justify-center">
                    {user?.avatar_url ? (
                      <Image src={user.avatar_url} alt="" width={80} height={80} sizes="80px" className="h-full w-full object-cover" />
                    ) : (
                      <span className="text-2xl font-semibold text-muted-foreground">
                        {(user?.username || '?').slice(0, 2).toUpperCase()}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={avatarUploading}
                    className="absolute inset-0 flex items-center justify-center rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
                    aria-label="Upload avatar"
                  >
                    <Upload className="h-5 w-5 text-white" />
                  </button>
                </div>
                <div className="space-y-2 flex-1">
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()} disabled={avatarUploading}>
                      {avatarUploading ? <><LoadingSpinner size="sm" className="mr-2" inline /> Uploading...</> : <><Upload className="h-4 w-4 mr-2" /> Upload</>}
                    </Button>
                    {user?.avatar_url && user.avatar_url.includes('/api/avatars/') && (
                      <Button variant="outline" size="sm" onClick={() => setConfirmAvatarDelete(true)} disabled={avatarDeleting}>
                        {avatarDeleting ? <LoadingSpinner size="sm" inline /> : <><X className="h-4 w-4 mr-2" /> Remove</>}
                      </Button>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">PNG, JPEG, WebP or GIF. Max 5 MB. Will be resized to 256×256.</p>
                </div>
              </div>
              <input ref={fileInputRef} type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden" onChange={(e) => void handleAvatarUpload(e)} />
              {/* Gravatar toggle — only shown when no custom avatar is set */}
              {!(user?.avatar_url && user.avatar_url.includes('/api/avatars/')) && (
                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <Label htmlFor="gravatar-toggle" className="text-sm font-medium">Use Gravatar</Label>
                    <p className="text-xs text-muted-foreground">Use your Gravatar as fallback when no custom avatar is set</p>
                  </div>
                  <Switch
                    id="gravatar-toggle"
                    checked={user?.use_gravatar !== false}
                    onCheckedChange={(checked) => void handleGravatarToggle(checked)}
                    disabled={gravatarToggling}
                  />
                </div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><User className="h-5 w-5" /> Profile Information</CardTitle>
              <CardDescription>Update your account details</CardDescription>
            </CardHeader>
            <CardContent>
              {formState.profile.success && (<Alert className="border-primary/50 bg-primary/10 mb-4"><CheckCircle className="h-4 w-4 text-primary" /><AlertDescription className="text-primary">{formState.profile.success}</AlertDescription></Alert>)}
              {formState.profile.error && (<Alert variant="destructive" className="mb-4"><AlertCircle className="h-4 w-4" /><AlertDescription>{formState.profile.error}</AlertDescription></Alert>)}
              <form onSubmit={handleUpdateProfile} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter username" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  {user?.is_admin ? (
                    <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Enter email" />
                  ) : availableEmails.length > 1 ? (
                    <>
                      <Select value={email} onValueChange={setEmail}>
                        <SelectTrigger className="w-full" aria-label="Select email"><SelectValue placeholder="Select email" /></SelectTrigger>
                        <SelectContent>{availableEmails.map(e => (<SelectItem key={e} value={e}>{e}</SelectItem>))}</SelectContent>
                      </Select>
                      <p className="text-sm text-muted-foreground">You can choose from your linked OAuth provider emails</p>
                    </>
                  ) : (
                    <><Input id="email" type="email" value={email} disabled /><p className="text-sm text-muted-foreground">Link an OAuth account with a different email to change it</p></>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <Label>Role:</Label>
                  {user?.is_super_admin ? (<Badge variant="default" className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600 text-white"><Shield className="h-3 w-3" /> Super Admin</Badge>)
                    : user?.is_admin ? (<Badge variant="default" className="gap-1"><Shield className="h-3 w-3" /> Admin</Badge>)
                    : (<Badge variant="outline">User</Badge>)}
                </div>
                <Button type="submit" disabled={updateProfileMutation.isPending}>
                  {updateProfileMutation.isPending ? <><LoadingSpinner size="sm" className="mr-2" inline /> Updating...</> : 'Update Profile'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ===================== Security Tab ===================== */}
        <TabsContent value="security" className="space-y-4 mt-4">
          {/* Password */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Lock className="h-5 w-5" /> {user?.has_password ? 'Change Password' : 'Set Password'}</CardTitle>
              <CardDescription>{user?.has_password ? 'Update your password to keep your account secure' : 'Set a password to enable email/password login alongside your social accounts'}</CardDescription>
            </CardHeader>
            <CardContent>
              {formState.password.success && (<Alert className="border-primary/50 bg-primary/10 mb-4"><CheckCircle className="h-4 w-4 text-primary" /><AlertDescription className="text-primary">{formState.password.success}</AlertDescription></Alert>)}
              {formState.password.error && (<Alert variant="destructive" className="mb-4"><AlertCircle className="h-4 w-4" /><AlertDescription>{formState.password.error}</AlertDescription></Alert>)}
              <form onSubmit={handleUpdatePassword} className="space-y-4">
                {user?.has_password && (
                  <div className="space-y-2"><Label htmlFor="current-password">Current Password</Label><Input id="current-password" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Enter current password" /></div>
                )}
                <div className="space-y-2"><Label htmlFor="new-password">{user?.has_password ? 'New Password' : 'Password'}</Label><Input id="new-password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Enter new password (min 8 characters)" /></div>
                <div className="space-y-2"><Label htmlFor="confirm-password">Confirm Password</Label><Input id="confirm-password" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm password" /></div>
                <Button type="submit" disabled={updatePasswordMutation.isPending || setPasswordMutation.isPending}>
                  {(updatePasswordMutation.isPending || setPasswordMutation.isPending)
                    ? <><LoadingSpinner size="sm" className="mr-2" inline /> {user?.has_password ? 'Updating...' : 'Setting...'}</>
                    : (user?.has_password ? 'Change Password' : 'Set Password')}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* TOTP 2FA */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" /> Authenticator App (TOTP)</CardTitle>
              <CardDescription>Use an authenticator app like Google Authenticator or Authy</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Status:</span>
                {twoFactorStatus?.enabled ? (<Badge variant="default" className="gap-1"><Shield className="h-3 w-3" /> Enabled</Badge>) : (<Badge variant="outline">Disabled</Badge>)}
              </div>
              {twoFactorStatus?.enabled ? (
                <Alert><Shield className="h-4 w-4" /><AlertDescription>You&apos;ll be asked for a verification code when logging in. Keep your authenticator app accessible.</AlertDescription></Alert>
              ) : (
                <p className="text-sm text-muted-foreground">Add an extra layer of security by requiring a verification code when you log in.</p>
              )}
              {twoFactorStatus?.enabled
                ? <Button variant="destructive" onClick={() => setDisableTwoFactorDialog(true)}>Disable 2FA</Button>
                : <Button onClick={() => setTwoFactorDialog(true)}>Enable 2FA</Button>}
            </CardContent>
          </Card>

          {/* Passkeys */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Fingerprint className="h-5 w-5" /> Passkeys &amp; Hardware Keys</CardTitle>
              <CardDescription>Sign in with biometrics, security keys, or device passkeys</CardDescription>
            </CardHeader>
            <CardContent>
              <PasskeyManager />
            </CardContent>
          </Card>

          {/* Active Sessions Manager */}
          <SessionManager />

          {/* Delete Account */}
          <Card className="border-destructive/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-destructive"><Trash2 className="h-5 w-5" /> Delete Account</CardTitle>
              <CardDescription>Permanently delete your account and all associated data</CardDescription>
            </CardHeader>
            <CardContent className="mt-2 space-y-4">
              <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>This action cannot be undone. All your rules, alerts, and webhooks will be permanently deleted.</AlertDescription></Alert>
              <Button variant="destructive" onClick={() => { setDeleteError(''); setDeleteDialog(true) }}><Trash2 className="h-4 w-4 mr-2" /> Delete Account</Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ===================== OAuth Tab ===================== */}
        <TabsContent value="oauth" className="space-y-4 mt-4">
          <LinkedAccounts />
        </TabsContent>

        {/* ===================== Logs Tab ===================== */}
        <TabsContent value="logs" className="space-y-4 mt-4">
          <SecurityHistory />

          {/* Data Export (GDPR) */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Download className="h-5 w-5" /> Export My Data</CardTitle>
              <CardDescription>Download all your personal data (GDPR Art. 20 — Right to data portability)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">Export all your data (profile, rules, webhooks, alerts, audit logs) as a JSON file.</p>
              <Button variant="outline" onClick={() => setExportDialog(true)}>
                <Download className="h-4 w-4 mr-2" /> Export My Data
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Dialogs */}
      <ConfirmDialog
        open={confirmAvatarDelete}
        onOpenChange={setConfirmAvatarDelete}
        title="Remove Avatar"
        description="Are you sure you want to remove your custom avatar? You can always upload a new one later."
        confirmText="Remove"
        variant="destructive"
        onConfirm={() => void handleAvatarDelete()}
      />

      <TwoFactorSetup open={twoFactorDialog} onOpenChange={setTwoFactorDialog} />

      <ConfirmDialog
        open={exportDialog}
        onOpenChange={setExportDialog}
        title="Export My Data"
        description="This will download all your personal data (profile, rules, webhooks, alerts, audit logs) as a JSON file."
        confirmText="Export"
        onConfirm={() => {
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
                setTimeout(() => URL.revokeObjectURL(url), 1000)
                toast({ title: '✅ Data exported', description: 'Your data has been downloaded' })
              }
            } catch (error) {
              toast({ variant: 'destructive', title: '❌ Export failed', description: extractErrorMessage(error, 'Failed to export data') })
            }
          })()
        }}
      />

      <Dialog open={disableTwoFactorDialog} onOpenChange={setDisableTwoFactorDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication?</DialogTitle>
            <DialogDescription>{user?.has_password ? 'Enter your password to confirm disabling 2FA' : 'Enter a 2FA code from your authenticator app to confirm'}</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleDisable2FA}>
            <div className="space-y-4">
              {formState.twoFactor.error && (<Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{formState.twoFactor.error}</AlertDescription></Alert>)}
              <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>Your account will be less secure without 2FA protection.</AlertDescription></Alert>
              <div className="space-y-2">
                <Label htmlFor="2fa-password">{user?.has_password ? 'Password' : '2FA Code'}</Label>
                <Input id="2fa-password" type={user?.has_password ? 'password' : 'text'} inputMode={user?.has_password ? undefined : 'numeric'} maxLength={user?.has_password ? undefined : 8} value={twoFactorPassword} onChange={(e) => setTwoFactorPassword(e.target.value)} placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'} />
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button type="button" variant="outline" onClick={() => { setDisableTwoFactorDialog(false); setTwoFactorPassword(''); clear('twoFactor') }}>Cancel</Button>
              <Button type="submit" variant="destructive" disabled={!twoFactorPassword || disableTwoFactorMutation.isPending}>
                {disableTwoFactorMutation.isPending ? <><LoadingSpinner size="sm" inline /><span className="ml-2">Disabling...</span></> : 'Disable 2FA'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Are you absolutely sure?</DialogTitle>
            <DialogDescription>This will permanently delete your account and all associated data.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription><strong>Warning:</strong> You will lose access to:<ul className="list-disc list-inside mt-2"><li>{stats?.rules_count || 0} active rules</li><li>{stats?.alerts_count || 0} alert history</li><li>{stats?.webhooks_count || 0} webhook configurations</li></ul></AlertDescription></Alert>
            <div className="space-y-2">
              <Label htmlFor="delete-confirm">Type your username to confirm: <strong>{user?.username}</strong></Label>
              <Input id="delete-confirm" value={deleteConfirmText} onChange={(e) => setDeleteConfirmText(e.target.value)} placeholder={user?.username} />
            </div>
            {(user?.has_password || twoFactorStatus?.enabled) && (
              <div className="space-y-2">
                <Label htmlFor="delete-password">{user?.has_password ? 'Enter your password' : 'Enter your 2FA code'}</Label>
                <Input id="delete-password" type={user?.has_password ? 'password' : 'text'} inputMode={user?.has_password ? undefined : 'numeric'} maxLength={user?.has_password ? undefined : 8} value={deletePassword} onChange={(e) => setDeletePassword(e.target.value)} placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'} />
              </div>
            )}            {deleteError && (
              <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{deleteError}</AlertDescription></Alert>
            )}          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setDeleteDialog(false); setDeleteConfirmText(''); setDeletePassword(''); setDeleteError('') }}>Cancel</Button>
            <Button variant="destructive" onClick={handleDeleteAccount} disabled={deleteConfirmText !== user?.username || ((user?.has_password || twoFactorStatus?.enabled) && !deletePassword) || deleteAccountMutation.isPending}>
              {deleteAccountMutation.isPending ? <><LoadingSpinner size="sm" inline /><span className="ml-2">Deleting...</span></> : 'Delete My Account'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

// ==================== Linked OAuth Accounts ====================

function LinkedAccounts() {
  const { toast } = useToast()
  const [unlinking, setUnlinking] = useState<string | null>(null)
  const [confirmUnlink, setConfirmUnlink] = useState<string | null>(null)
  const [confirmLink, setConfirmLink] = useState<string | null>(null)
  // Keep last non-null value so dialog text stays stable during close animation
  const lastUnlinkProvider = useRef<string>('')
  const lastLinkProvider = useRef<string>('')
  if (confirmUnlink) lastUnlinkProvider.current = confirmUnlink
  if (confirmLink) lastLinkProvider.current = confirmLink
  const unlinkLabel = PROVIDER_META[lastUnlinkProvider.current]?.label ?? lastUnlinkProvider.current
  const linkLabel = PROVIDER_META[lastLinkProvider.current]?.label ?? lastLinkProvider.current

  const { data: enabledProviders, isLoading: isLoadingProviders } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: async () => { const res = await apiClient.getOAuthProviders(); return res.success ? (res.data?.providers ?? []) : [] },
    staleTime: 5 * 60 * 1000,
  })

  const { data: accounts, refetch } = useQuery({
    queryKey: ['oauth-accounts'],
    queryFn: async () => { const res = await apiClient.getOAuthAccounts(); return res.success ? (res.data ?? []) : [] },
    staleTime: 30_000,
  })

  const handleUnlink = async (provider: string) => {
    setUnlinking(provider)
    try {
      const res = await apiClient.unlinkOAuthAccount(provider)
      if (res.success) { toast({ title: '✅ Account unlinked', description: `${PROVIDER_META[provider]?.label ?? provider} account has been unlinked.` }); void refetch() }
      else { toast({ variant: 'destructive', title: '❌ Unlink failed', description: res.message || 'Could not unlink account.' }) }
    } catch (err) { toast({ variant: 'destructive', title: '❌ Unlink failed', description: extractErrorMessage(err, 'Could not unlink account.') }) }
    finally { setUnlinking(null) }
  }

  const handleLink = (provider: string) => { window.location.href = apiClient.getOAuthLoginUrl(provider) }

  const linkedProviders = useMemo(() => new Set((accounts ?? []).map(a => a.provider)), [accounts])

  if (isLoadingProviders) return <LinkedAccountsSkeleton />
  if (!enabledProviders || enabledProviders.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" /> Linked Accounts</CardTitle>
        <CardDescription>Manage your social login connections</CardDescription>
      </CardHeader>
      <CardContent className="mt-2 space-y-2">
        {enabledProviders.map(provider => {
          const meta = PROVIDER_META[provider] ?? { label: provider, icon: null }
          const isLinked = linkedProviders.has(provider)
          const account = (accounts ?? []).find(a => a.provider === provider)
          return (
            <div key={provider} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex items-center gap-3">
                <div className="flex items-center justify-center h-9 w-9 rounded-md bg-muted/50 shrink-0">
                  {meta.icon}
                </div>
                <div>
                  <p className="text-sm font-medium">{meta.label}</p>
                  {isLinked && account?.provider_email && (<p className="text-xs text-muted-foreground">{account.provider_email}</p>)}
                </div>
              </div>
              {isLinked
                ? <Button variant="outline" size="sm" disabled={unlinking === provider} onClick={() => setConfirmUnlink(provider)}>{unlinking === provider ? <LoadingSpinner size="sm" inline /> : 'Unlink'}</Button>
                : <Button variant="outline" size="sm" onClick={() => setConfirmLink(provider)}>Link</Button>}
            </div>
          )
        })}
      </CardContent>
      <ConfirmDialog
        open={!!confirmUnlink}
        onOpenChange={(open) => { if (!open) setConfirmUnlink(null) }}
        title="Unlink account?"
        description={`Are you sure you want to unlink your ${unlinkLabel} account? You can always re-link it later.`}
        confirmText="Unlink"
        variant="destructive"
        onConfirm={() => { if (confirmUnlink) void handleUnlink(confirmUnlink) }}
      />
      <ConfirmDialog
        open={!!confirmLink}
        onOpenChange={(open) => { if (!open) setConfirmLink(null) }}
        title={`Link ${linkLabel} account?`}
        description={`You will be redirected to ${linkLabel} to authorize your account. You can unlink it at any time.`}
        confirmText="Continue"
        onConfirm={() => { if (confirmLink) handleLink(confirmLink) }}
      />
    </Card>
  )
}
