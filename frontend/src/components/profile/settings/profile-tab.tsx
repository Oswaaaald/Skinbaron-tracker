'use client'

import type { ChangeEvent, FormEvent, RefObject } from 'react'
import Image from 'next/image'
import { Camera, CheckCircle, Shield, Upload, User, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

interface UserLike {
  username?: string
  email?: string
  avatar_url?: string | null
  use_gravatar?: boolean
  is_admin?: boolean
  is_super_admin?: boolean
}

interface ProfileFeedback {
  success?: string
  error?: string
}

interface ProfileTabProps {
  user: UserLike | null
  username: string
  email: string
  availableEmails: string[]
  fileInputRef: RefObject<HTMLInputElement | null>
  avatarUploading: boolean
  avatarDeleting: boolean
  gravatarToggling: boolean
  profilePending: boolean
  feedback: ProfileFeedback
  onUsernameChange: (value: string) => void
  onEmailChange: (value: string) => void
  onUploadAvatar: (e: ChangeEvent<HTMLInputElement>) => Promise<void> | void
  onToggleGravatar: (checked: boolean) => Promise<void> | void
  onSubmitProfile: (e: FormEvent) => void
  onAskAvatarDelete: () => void
}

export function ProfileTab({
  user,
  username,
  email,
  availableEmails,
  fileInputRef,
  avatarUploading,
  avatarDeleting,
  gravatarToggling,
  profilePending,
  feedback,
  onUsernameChange,
  onEmailChange,
  onUploadAvatar,
  onToggleGravatar,
  onSubmitProfile,
  onAskAvatarDelete,
}: ProfileTabProps) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Camera className="h-5 w-5" /> Avatar
          </CardTitle>
          <CardDescription>Upload a custom avatar or use your Gravatar</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-6">
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
                  {avatarUploading ? (
                    <>
                      <LoadingSpinner size="sm" className="mr-2" inline /> Uploading...
                    </>
                  ) : (
                    <>
                      <Upload className="h-4 w-4 mr-2" /> Upload
                    </>
                  )}
                </Button>
                {user?.avatar_url && user.avatar_url.includes('/api/avatars/') && (
                  <Button variant="outline" size="sm" onClick={onAskAvatarDelete} disabled={avatarDeleting}>
                    {avatarDeleting ? <LoadingSpinner size="sm" inline /> : <><X className="h-4 w-4 mr-2" /> Remove</>}
                  </Button>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                PNG, JPEG, WebP or GIF. Max 5 MB. Will be resized to 256×256.
              </p>
            </div>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp,image/gif"
            className="hidden"
            onChange={(e) => void onUploadAvatar(e)}
          />

          {!(user?.avatar_url && user.avatar_url.includes('/api/avatars/')) && (
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="gravatar-toggle" className="text-sm font-medium">Use Gravatar</Label>
                <p className="text-xs text-muted-foreground">
                  Use your Gravatar as fallback when no custom avatar is set
                </p>
              </div>
              <Switch
                id="gravatar-toggle"
                checked={user?.use_gravatar !== false}
                onCheckedChange={(checked) => void onToggleGravatar(checked)}
                disabled={gravatarToggling}
              />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" /> Profile Information
          </CardTitle>
          <CardDescription>Update your account details</CardDescription>
        </CardHeader>
        <CardContent>
          {feedback.success && (
            <Alert className="border-primary/50 bg-primary/10 mb-4">
              <CheckCircle className="h-4 w-4 text-primary" />
              <AlertDescription className="text-primary">{feedback.success}</AlertDescription>
            </Alert>
          )}
          {feedback.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{feedback.error}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={onSubmitProfile} className="space-y-5">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => onUsernameChange(e.target.value)}
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
                    onChange={(e) => onEmailChange(e.target.value)}
                    placeholder="Enter email"
                  />
                ) : availableEmails.length > 1 ? (
                  <>
                    <Select value={email} onValueChange={onEmailChange}>
                      <SelectTrigger className="w-full" aria-label="Select email">
                        <SelectValue placeholder="Select email" />
                      </SelectTrigger>
                      <SelectContent>
                        {availableEmails.map((entry) => (
                          <SelectItem key={entry} value={entry}>
                            {entry}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-sm text-muted-foreground">
                      You can choose from your linked OAuth provider emails
                    </p>
                  </>
                ) : (
                  <>
                    <Input id="email" type="email" value={email} disabled />
                    <p className="text-sm text-muted-foreground">
                      Link an OAuth account with a different email to change it
                    </p>
                  </>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <Label>Role:</Label>
              {user?.is_super_admin ? (
                <Badge variant="default" className="gap-1 !border-transparent !bg-gradient-to-r !from-purple-600 !to-pink-600 !text-white">
                  <Shield className="h-3 w-3" /> Super Admin
                </Badge>
              ) : user?.is_admin ? (
                <Badge variant="default" className="gap-1">
                  <Shield className="h-3 w-3" /> Admin
                </Badge>
              ) : (
                <Badge variant="outline">User</Badge>
              )}
              <Button type="submit" disabled={profilePending}>
                {profilePending ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-2" inline /> Updating...
                  </>
                ) : (
                  'Update Profile'
                )}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
