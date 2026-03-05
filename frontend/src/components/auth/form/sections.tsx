'use client'

import { Eye, EyeOff, Lock, Mail, Shield, User } from 'lucide-react'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { sanitizeTotpInput } from '@/components/auth/form/helpers'

interface SharedFormData {
  username: string
  email: string
  password: string
  confirmPassword: string
  tosAccepted: boolean
}

interface OAuthPendingData {
  email: string
  provider: string
}

export function OAuthFinalizeSection({
  oauthPendingData,
  formData,
  isLoading,
  onUsernameChange,
  onTosChange,
}: {
  oauthPendingData: OAuthPendingData
  formData: SharedFormData
  isLoading: boolean
  onUsernameChange: (value: string) => void
  onTosChange: (checked: boolean) => void
}) {
  return (
    <div className="space-y-4">
      <Alert>
        <AlertDescription>
          You&apos;re signing up with <strong className="capitalize">{oauthPendingData.provider}</strong>. Choose your username and accept the terms to create your account.
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        <Label htmlFor="oauth-email">Email</Label>
        <div className="relative">
          <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input id="oauth-email" type="email" value={oauthPendingData.email} className="pl-10 bg-muted" disabled />
        </div>
        <p className="text-xs text-muted-foreground">
          Email from your {oauthPendingData.provider} account (cannot be changed)
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="oauth-username">Username</Label>
        <div className="relative">
          <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            id="oauth-username"
            type="text"
            placeholder="Choose a username"
            value={formData.username}
            onChange={(e) => onUsernameChange(e.target.value)}
            className="pl-10"
            disabled={isLoading}
            maxLength={20}
            autoFocus
          />
        </div>
        <p className="text-xs text-muted-foreground">3–20 characters, letters, numbers and underscores only</p>
      </div>

      <div className="flex items-start gap-2">
        <input
          id="oauth-tos"
          type="checkbox"
          checked={formData.tosAccepted}
          onChange={(e) => onTosChange(e.target.checked)}
          disabled={isLoading}
          className="mt-1 h-4 w-4 rounded border-border accent-primary"
        />
        <Label htmlFor="oauth-tos" className="text-sm font-normal leading-snug">
          I agree to the{' '}
          <Link href="/tos" target="_blank" className="underline hover:text-foreground">Terms of Service</Link>{' '}
          and{' '}
          <Link href="/privacy" target="_blank" className="underline hover:text-foreground">Privacy Policy</Link>
        </Label>
      </div>
    </div>
  )
}

export function TwoFactorSection({
  totpCode,
  isLoading,
  onCodeChange,
}: {
  totpCode: string
  isLoading: boolean
  onCodeChange: (value: string) => void
}) {
  return (
    <div className="space-y-4">
      <Alert>
        <Shield className="h-4 w-4" />
        <AlertDescription>
          Enter the 6-digit code from your authenticator app. You can also use a recovery code.
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        <Label htmlFor="totp-code">Authentication Code</Label>
        <Input
          id="totp-code"
          type="text"
          maxLength={8}
          placeholder="000000"
          value={totpCode}
          onChange={(e) => onCodeChange(sanitizeTotpInput(e.target.value))}
          className="text-center text-2xl tracking-widest font-mono"
          autoComplete="off"
          autoFocus
          disabled={isLoading}
        />
        <p className="text-sm text-muted-foreground text-center">
          Enter 6-digit code or 8-character recovery code
        </p>
      </div>
    </div>
  )
}

export function CredentialsSection({
  isLogin,
  showPassword,
  isLoading,
  formData,
  onInputChange,
  onToggleTos,
  onToggleShowPassword,
}: {
  isLogin: boolean
  showPassword: boolean
  isLoading: boolean
  formData: SharedFormData
  onInputChange: (field: keyof SharedFormData, value: string) => void
  onToggleTos: (checked: boolean) => void
  onToggleShowPassword: () => void
}) {
  return (
    <>
      {!isLogin && (
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <div className="relative">
            <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              id="username"
              type="text"
              placeholder="Your username"
              value={formData.username}
              onChange={(e) => onInputChange('username', e.target.value)}
              className="pl-10"
              disabled={isLoading}
              maxLength={20}
            />
          </div>
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <div className="relative">
          <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            id="email"
            type="email"
            placeholder="your@email.com"
            value={formData.email}
            onChange={(e) => onInputChange('email', e.target.value)}
            className="pl-10"
            disabled={isLoading}
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <div className="relative">
          <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            id="password"
            type={showPassword ? 'text' : 'password'}
            placeholder="Your password"
            value={formData.password}
            onChange={(e) => onInputChange('password', e.target.value)}
            className="pl-10 pr-10"
            disabled={isLoading}
          />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
            onClick={onToggleShowPassword}
            disabled={isLoading}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff className="h-4 w-4 text-muted-foreground" /> : <Eye className="h-4 w-4 text-muted-foreground" />}
          </Button>
        </div>
      </div>

      {!isLogin && (
        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm Password</Label>
          <div className="relative">
            <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              id="confirmPassword"
              type={showPassword ? 'text' : 'password'}
              placeholder="Confirm your password"
              value={formData.confirmPassword}
              onChange={(e) => onInputChange('confirmPassword', e.target.value)}
              className="pl-10"
              disabled={isLoading}
            />
          </div>
        </div>
      )}

      {!isLogin && (
        <div className="flex items-start gap-2">
          <input
            id="tos"
            type="checkbox"
            checked={formData.tosAccepted}
            onChange={(e) => onToggleTos(e.target.checked)}
            disabled={isLoading}
            className="mt-1 h-4 w-4 rounded border-border accent-primary"
          />
          <Label htmlFor="tos" className="text-sm font-normal leading-snug">
            I agree to the <Link href="/tos" target="_blank" className="underline hover:text-foreground">Terms of Service</Link>{' '}
            and <Link href="/privacy" target="_blank" className="underline hover:text-foreground">Privacy Policy</Link>
          </Label>
        </div>
      )}
    </>
  )
}
