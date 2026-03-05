'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, CheckCircle, History, Link2, Shield, User } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from '@/lib/constants'
import { PROVIDER_META } from '@/lib/oauth-icons'
import { validateEmail, validatePasswordChange, validateSetPassword, validateUsername } from '@/lib/validation'
import { canAccessAdmin } from '@/lib/rbac'
import { useAuth } from '@/contexts/auth-context'
import { useFormState } from '@/hooks/use-form-state'
import { usePageVisible } from '@/hooks/use-page-visible'
import { useToast } from '@/hooks/use-toast'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ProfileSkeleton } from '@/components/ui/skeletons'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TwoFactorSetup } from '@/components/auth/two-factor-setup'
import { exportUserData } from '@/components/profile/settings/export-data'
import { LogsTab } from '@/components/profile/settings/logs-tab'
import { ProfileSettingsDialogs } from '@/components/profile/settings/dialogs'
import { LinkedAccounts } from '@/components/profile/settings/linked-accounts'
import { ProfileTab } from '@/components/profile/settings/profile-tab'
import { SecurityTab } from '@/components/profile/settings/security-tab'
import { ProfileSettingsStatsCards, type UserStats } from '@/components/profile/settings/stats-cards'
import { useAvatarActions } from '@/components/profile/settings/use-avatar-actions'
import { useProfileMutations } from '@/components/profile/settings/use-profile-mutations'

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
  const [deleteError, setDeleteError] = useState('')
  const [twoFactorDialog, setTwoFactorDialog] = useState(false)
  const [disableTwoFactorDialog, setDisableTwoFactorDialog] = useState(false)
  const [twoFactorPassword, setTwoFactorPassword] = useState('')
  const [exportDialog, setExportDialog] = useState(false)
  const [confirmAvatarDelete, setConfirmAvatarDelete] = useState(false)
  const [activeTab, setActiveTab] = useState('profile')

  const fileInputRef = useRef<HTMLInputElement>(null)
  const { avatarUploading, avatarDeleting, gravatarToggling, handleAvatarUpload, handleAvatarDelete, handleGravatarToggle } = useAvatarActions({ updateUser, toast })

  const {
    updateProfileMutation,
    updatePasswordMutation,
    setPasswordMutation,
    deleteAccountMutation,
    disableTwoFactorMutation,
  } = useProfileMutations({
    user,
    updateUser,
    logout,
    toast,
    setError,
    setSuccess,
    clear,
    setDeleteError,
    setDeletePassword,
    setCurrentPassword,
    setNewPassword,
    setConfirmPassword,
    setDisableTwoFactorDialog,
    setTwoFactorPassword,
  })

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    if (params.has('linked') || params.has('link_error')) setActiveTab('oauth')
  }, [])

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
      const errors: Record<string, string> = {
        already_linked_other: 'This social account is already linked to another user.',
        account_not_found: 'Your account was not found. Please log in again.',
        rate_limited: 'Too many attempts. Please try again in a moment.',
        server_error: 'An unexpected error occurred. Please try again.',
      }
      toast({ variant: 'destructive', title: '❌ Link failed', description: errors[linkError] || 'Could not link account.' })
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
    if (!user) return
    setUsername(user.username)
    setEmail(user.email)
  }, [user])

  const { data: stats, isLoading: isLoadingStats } = useQuery({
    queryKey: [QUERY_KEYS.USER_STATS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.get('/api/user/stats'), 'Failed to load user stats').data as UserStats,
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

  const { data: twoFactorStatus } = useQuery({
    queryKey: [QUERY_KEYS.TWO_FA_STATUS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.get('/api/user/2fa/status'), 'Failed to load 2FA status').data as { enabled: boolean },
    enabled: isReady && isAuthenticated,
  })

  const availableEmails = useMemo(() => {
    if (canAccessAdmin(user)) return []
    const emails = new Set<string>()
    if (user?.email) emails.add(user.email)
    for (const account of oauthAccounts ?? []) if (account.provider_email) emails.add(account.provider_email)
    return [...emails]
  }, [user, oauthAccounts])

  const handleUpdateProfile = (e: React.FormEvent) => {
    e.preventDefault(); clear('profile')
    const updates: { username?: string; email?: string } = {}
    if (username !== user?.username) {
      const result = validateUsername(username)
      if (!result.valid) return setError('profile', result.error || 'Invalid username')
      updates.username = username
    }
    if (email !== user?.email) {
      const result = validateEmail(email)
      if (!result.valid) return setError('profile', result.error || 'Invalid email')
      updates.email = email
    }
    if (Object.keys(updates).length === 0) return setError('profile', 'No changes to save')
    updateProfileMutation.mutate(updates)
  }

  const handleUpdatePassword = (e: React.FormEvent) => {
    e.preventDefault(); clear('password')
    if (!user?.has_password) {
      const result = validateSetPassword({ newPassword, confirmPassword })
      if (!result.valid) return setError('password', result.error || 'Validation failed')
      setPasswordMutation.mutate({ new_password: newPassword })
      return
    }
    const result = validatePasswordChange({ currentPassword, newPassword, confirmPassword })
    if (!result.valid) return setError('password', result.error || 'Validation failed')
    updatePasswordMutation.mutate({ current_password: currentPassword, new_password: newPassword })
  }

  const handleDeleteAccount = () => {
    if (deleteConfirmText !== user?.username) return
    if (user?.has_password) { if (deletePassword) deleteAccountMutation.mutate({ password: deletePassword }); return }
    if (twoFactorStatus?.enabled) { if (deletePassword) deleteAccountMutation.mutate({ totp_code: deletePassword }); return }
    deleteAccountMutation.mutate({})
  }

  const handleDisable2FA = (e: React.FormEvent) => {
    e.preventDefault()
    if (user?.has_password) { if (twoFactorPassword) disableTwoFactorMutation.mutate({ password: twoFactorPassword }) }
    else if (twoFactorPassword) disableTwoFactorMutation.mutate({ totp_code: twoFactorPassword })
  }

  if (isLoadingStats) return <ProfileSkeleton />

  return (
    <div className="space-y-6">
      {formState.general.success && <Alert className="border-primary/50 bg-primary/10"><CheckCircle className="h-4 w-4 text-primary" /><AlertDescription className="text-primary">{formState.general.success}</AlertDescription></Alert>}
      {formState.general.error && <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{formState.general.error}</AlertDescription></Alert>}

      <ProfileSettingsStatsCards stats={stats} />

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="h-auto w-full gap-1 p-1">
          <TabsTrigger value="profile" className="flex items-center gap-1.5"><User className="h-4 w-4" /><span className="hidden sm:inline">Profile</span></TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-1.5"><Shield className="h-4 w-4" /><span className="hidden sm:inline">Security</span></TabsTrigger>
          <TabsTrigger value="oauth" className="flex items-center gap-1.5"><Link2 className="h-4 w-4" /><span className="hidden sm:inline">Accounts</span></TabsTrigger>
          <TabsTrigger value="logs" className="flex items-center gap-1.5"><History className="h-4 w-4" /><span className="hidden sm:inline">Logs</span></TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="mt-5 space-y-5">
          <ProfileTab
            user={user}
            username={username}
            email={email}
            availableEmails={availableEmails}
            fileInputRef={fileInputRef}
            avatarUploading={avatarUploading}
            avatarDeleting={avatarDeleting}
            gravatarToggling={gravatarToggling}
            profilePending={updateProfileMutation.isPending}
            feedback={{ success: formState.profile.success, error: formState.profile.error }}
            onUsernameChange={setUsername}
            onEmailChange={setEmail}
            onUploadAvatar={handleAvatarUpload}
            onToggleGravatar={handleGravatarToggle}
            onSubmitProfile={handleUpdateProfile}
            onAskAvatarDelete={() => setConfirmAvatarDelete(true)}
          />
        </TabsContent>

        <TabsContent value="security" className="mt-5 space-y-5">
          <SecurityTab
            user={user}
            passwordFeedback={{ success: formState.password.success, error: formState.password.error }}
            currentPassword={currentPassword}
            newPassword={newPassword}
            confirmPassword={confirmPassword}
            twoFactorEnabled={twoFactorStatus?.enabled}
            updatePasswordPending={updatePasswordMutation.isPending}
            setPasswordPending={setPasswordMutation.isPending}
            onCurrentPasswordChange={setCurrentPassword}
            onNewPasswordChange={setNewPassword}
            onConfirmPasswordChange={setConfirmPassword}
            onSubmitPassword={handleUpdatePassword}
            onOpenEnable2FA={() => setTwoFactorDialog(true)}
            onOpenDisable2FA={() => setDisableTwoFactorDialog(true)}
            onOpenDeleteAccount={() => { setDeleteError(''); setDeleteDialog(true) }}
          />
        </TabsContent>

        <TabsContent value="oauth" className="mt-5 space-y-5"><LinkedAccounts /></TabsContent>
        <TabsContent value="logs" className="mt-5 space-y-5"><LogsTab onOpenExport={() => setExportDialog(true)} /></TabsContent>
      </Tabs>

      <ProfileSettingsDialogs
        user={user}
        stats={stats}
        twoFactorEnabled={twoFactorStatus?.enabled}
        twoFactorError={formState.twoFactor.error}
        confirmAvatarDelete={confirmAvatarDelete}
        setConfirmAvatarDelete={setConfirmAvatarDelete}
        onConfirmAvatarDelete={() => void handleAvatarDelete()}
        exportDialog={exportDialog}
        setExportDialog={setExportDialog}
        onConfirmExport={() => void exportUserData(toast)}
        disableTwoFactorDialog={disableTwoFactorDialog}
        setDisableTwoFactorDialog={setDisableTwoFactorDialog}
        twoFactorPassword={twoFactorPassword}
        setTwoFactorPassword={setTwoFactorPassword}
        disableTwoFactorPending={disableTwoFactorMutation.isPending}
        onSubmitDisable2FA={handleDisable2FA}
        onResetTwoFactorForm={() => { setTwoFactorPassword(''); clear('twoFactor') }}
        deleteDialog={deleteDialog}
        setDeleteDialog={setDeleteDialog}
        deleteConfirmText={deleteConfirmText}
        setDeleteConfirmText={setDeleteConfirmText}
        deletePassword={deletePassword}
        setDeletePassword={setDeletePassword}
        deleteError={deleteError}
        deleteAccountPending={deleteAccountMutation.isPending}
        onConfirmDeleteAccount={handleDeleteAccount}
        onResetDeleteForm={() => { setDeleteConfirmText(''); setDeletePassword(''); setDeleteError('') }}
        twoFactorSetupElement={<TwoFactorSetup open={twoFactorDialog} onOpenChange={setTwoFactorDialog} />}
      />
    </div>
  )
}
