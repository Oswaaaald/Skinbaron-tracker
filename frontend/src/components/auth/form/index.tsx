'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AuthFormSkeleton } from '@/components/ui/skeletons'
import { AuthFormContent } from '@/components/auth/form/content'
import { useAuthFormController } from '@/components/auth/form/controller'
import type { AuthMode } from '@/components/auth/form/types'

interface AuthFormProps {
  mode: AuthMode
  onToggleMode: () => void
}

export function AuthForm({ mode, onToggleMode }: AuthFormProps) {
  const controller = useAuthFormController(mode, onToggleMode)

  if (!controller.oauthReady) {
    return <AuthFormSkeleton />
  }

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
      className="min-h-screen w-full flex items-center justify-center bg-background p-4 relative"
      style={{ minHeight: '100vh', paddingTop: '4rem', paddingBottom: '4rem' }}
    >
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,oklch(0.5_0_0/0.06),transparent)]" />
      <Card className="w-full max-w-md border-border/50 shadow-lg">
        <CardHeader className="space-y-1.5 text-center pb-2">
          <CardTitle className="text-2xl font-bold tracking-tight">{title}</CardTitle>
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
  )
}
