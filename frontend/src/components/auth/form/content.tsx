'use client'

import { Shield } from 'lucide-react'
import type { FormEvent, KeyboardEvent } from 'react'
import { apiClient } from '@/lib/api'
import { CredentialsSection, OAuthFinalizeSection, TwoFactorSection } from '@/components/auth/form/sections'
import { AuthErrorAlert, Divider, OAuthButtons, PasskeyButton, isTotpSubmitDisabled } from '@/components/auth/form/actions'
import type { AuthMode, AuthFormData, OAuthPendingData } from '@/components/auth/form/types'
import { Button } from '@/components/ui/button'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

interface AuthFormContentProps {
  mode: AuthMode
  onToggleMode: () => void
  isLoading: boolean
  error: string
  showPassword: boolean
  requires2FA: boolean
  oauthPending2FA: boolean
  oauthPendingRegistration: boolean
  oauthPendingData: OAuthPendingData | null
  totpCode: string
  oauthProviders: string[]
  formData: AuthFormData
  isLogin: boolean
  onSubmit: (e: FormEvent) => void
  onKeyDownSubmit: (e: KeyboardEvent<HTMLFormElement>) => void
  onToggleShowPassword: () => void
  onSetField: (field: keyof AuthFormData, value: string) => void
  onSetTosAccepted: (checked: boolean) => void
  onSetTotpCode: (value: string) => void
  onPasskeyLogin: () => void
  onCancelOAuthRegistration: () => void
  onBackFrom2FA: () => void
  onCancelOAuth2FA: () => void
}

export function AuthFormContent({
  mode,
  onToggleMode,
  isLoading,
  error,
  showPassword,
  requires2FA,
  oauthPending2FA,
  oauthPendingRegistration,
  oauthPendingData,
  totpCode,
  oauthProviders,
  formData,
  isLogin,
  onSubmit,
  onKeyDownSubmit,
  onToggleShowPassword,
  onSetField,
  onSetTosAccepted,
  onSetTotpCode,
  onPasskeyLogin,
  onCancelOAuthRegistration,
  onBackFrom2FA,
  onCancelOAuth2FA,
}: AuthFormContentProps) {
  return (
    <form onSubmit={(e) => { void onSubmit(e) }} onKeyDown={onKeyDownSubmit} className="space-y-4">
      {oauthPendingRegistration && oauthPendingData ? (
        <OAuthFinalizeSection
          oauthPendingData={oauthPendingData}
          formData={formData}
          isLoading={isLoading}
          onUsernameChange={(value) => onSetField('username', value)}
          onTosChange={onSetTosAccepted}
        />
      ) : (requires2FA || oauthPending2FA) ? (
        <TwoFactorSection totpCode={totpCode} isLoading={isLoading} onCodeChange={onSetTotpCode} />
      ) : (
        <CredentialsSection
          isLogin={isLogin}
          showPassword={showPassword}
          isLoading={isLoading}
          formData={formData}
          onInputChange={onSetField}
          onToggleTos={onSetTosAccepted}
          onToggleShowPassword={onToggleShowPassword}
        />
      )}

      <AuthErrorAlert error={error} />

      {oauthPendingRegistration ? (
        <>
          <Button type="submit" className="w-full" disabled={isLoading || !formData.tosAccepted}>
            {isLoading ? (
              <>
                <LoadingSpinner size="sm" inline />
                <span className="ml-2">Creating Account...</span>
              </>
            ) : (
              'Create Account'
            )}
          </Button>
          <Button
            type="button"
            variant="ghost"
            className="w-full"
            onClick={onCancelOAuthRegistration}
            disabled={isLoading}
          >
            Cancel
          </Button>
        </>
      ) : !requires2FA && !oauthPending2FA ? (
        <>
          <Button type="submit" className="w-full" disabled={isLoading || (!isLogin && !formData.tosAccepted)}>
            {isLoading ? (
              <>
                <LoadingSpinner size="sm" inline />
                <span className="ml-2">{isLogin ? 'Signing In...' : 'Creating Account...'}</span>
              </>
            ) : (
              isLogin ? 'Sign In' : 'Create Account'
            )}
          </Button>

          {isLogin && (
            <>
              <Divider label="Or" />
              <PasskeyButton isLoading={isLoading} onClick={onPasskeyLogin} />
            </>
          )}

          {oauthProviders.length > 0 && (
            <>
              <Divider label="Or continue with" />
              <OAuthButtons
                oauthProviders={oauthProviders}
                isLoading={isLoading}
                onClick={(provider) => {
                  window.location.href = apiClient.getOAuthLoginUrl(provider, isLogin ? 'login' : 'register')
                }}
              />
            </>
          )}

          <div className="text-center">
            <Button type="button" variant="link" className="text-sm" onClick={onToggleMode} disabled={isLoading}>
              {mode === 'login'
                ? "Don't have an account? Sign up"
                : 'Already have an account? Sign in'}
            </Button>
          </div>
        </>
      ) : (
        <>
          <Button type="submit" className="w-full" disabled={isTotpSubmitDisabled(isLoading, totpCode)}>
            {isLoading ? (
              <>
                <LoadingSpinner size="sm" inline />
                <span className="ml-2">Verifying...</span>
              </>
            ) : (
              <>
                <Shield className="mr-2 h-4 w-4" />
                {totpCode.length === 8 ? 'Verify Backup Code' : 'Verify Code'}
              </>
            )}
          </Button>

          {requires2FA && (
            <Button type="button" variant="ghost" className="w-full" onClick={onBackFrom2FA} disabled={isLoading}>
              Back to Login
            </Button>
          )}
          {oauthPending2FA && (
            <Button type="button" variant="outline" className="w-full" onClick={onCancelOAuth2FA} disabled={isLoading}>
              Cancel
            </Button>
          )}
        </>
      )}
    </form>
  )
}
