'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AuthFormContent } from '@/components/auth/form/content'
import { useAuthFormController } from '@/components/auth/form/controller'
import type { AuthMode } from '@/components/auth/form/types'

interface AuthFormProps {
  mode: AuthMode
  onToggleMode: () => void
}

export function AuthForm({ mode, onToggleMode }: AuthFormProps) {
  const controller = useAuthFormController(mode, onToggleMode)

  const title = controller.oauthPendingRegistration
    ? 'Finalize Registration'
    : (controller.requires2FA || controller.oauthPending2FA)
      ? 'Two-Factor Authentication'
      : (controller.isLogin ? 'Welcome Back' : 'Create Account')

  const description = controller.oauthPendingRegistration
    ? 'Choose your username and accept the terms to create your account'
    : (controller.requires2FA || controller.oauthPending2FA)
      ? 'Enter the code from your authenticator app'
      : (controller.isLogin
        ? 'Sign in to your SkinBaron Tracker account'
        : 'Get started with SkinBaron Tracker')

  return (
    <div
      className="relative flex min-h-[100dvh] w-full items-center justify-center overflow-hidden bg-background px-4 py-16"
    >
      <div className="w-full max-w-md space-y-4">
        <div className="flex items-center justify-center gap-3">
          <span
            aria-hidden="true"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border/70 bg-card text-[11px] font-semibold text-muted-foreground"
          >
            SB
          </span>
          <p className="text-sm font-semibold tracking-[0.04em] text-muted-foreground">SKINBARON TRACKER</p>
        </div>

        <Card className="w-full border-border/70 bg-card/85 shadow-xl">
          <CardHeader className="space-y-1.5 pb-2 text-center">
            <CardTitle className="text-2xl font-semibold tracking-tight">{title}</CardTitle>
          <CardDescription className="text-sm">{description}</CardDescription>
          </CardHeader>

          <CardContent>
            <AuthFormContent
              mode={mode}
              onToggleMode={onToggleMode}
              isLoading={controller.isLoading}
              error={controller.error}
              showPassword={controller.showPassword}
              requires2FA={controller.requires2FA}
              oauthPending2FA={controller.oauthPending2FA}
              oauthPendingRegistration={controller.oauthPendingRegistration}
              oauthPendingData={controller.oauthPendingData}
              totpCode={controller.totpCode}
              oauthProviders={controller.oauthProviders}
              formData={controller.formData}
              isLogin={controller.isLogin}
              onSubmit={(e) => { void controller.handleSubmit(e) }}
              onKeyDownSubmit={controller.handleKeyDownSubmit}
              onToggleShowPassword={() => controller.setShowPassword((prev) => !prev)}
              onSetField={controller.setField}
              onSetTosAccepted={controller.setTosAccepted}
              onSetTotpCode={(value) => {
                controller.setTotpCode(value)
                if (controller.error) controller.setError('')
              }}
              onPasskeyLogin={() => void controller.handlePasskeyLogin()}
              onCancelOAuthRegistration={() => {
                controller.setOauthPendingRegistration(false)
                controller.setOauthPendingData(null)
                controller.setError('')
                controller.setFormData((prev) => ({ ...prev, username: '', email: '', tosAccepted: false }))
              }}
              onBackFrom2FA={() => {
                controller.setRequires2FA(false)
                controller.setTotpCode('')
                controller.setError('')
              }}
              onCancelOAuth2FA={() => {
                controller.setOauthPending2FA(false)
                controller.setTotpCode('')
                controller.setError('')
              }}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
