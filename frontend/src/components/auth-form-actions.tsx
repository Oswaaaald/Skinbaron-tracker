'use client'

import { Fingerprint } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { OAUTH_PROVIDER_ORDER } from '@/components/auth-form.constants'
import { isValidTotpOrRecoveryCode } from '@/components/auth-form.helpers'
import { PROVIDER_ICONS, PROVIDER_LABELS } from '@/lib/oauth-icons'

export function Divider({ label }: { label: string }) {
  return (
    <div className="relative my-2">
      <div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div>
      <div className="relative flex justify-center text-xs uppercase"><span className="bg-card px-2 text-muted-foreground">{label}</span></div>
    </div>
  )
}

export function OAuthButtons({
  oauthProviders,
  isLoading,
  onClick,
}: {
  oauthProviders: string[]
  isLoading: boolean
  onClick: (provider: string) => void
}) {
  if (oauthProviders.length === 0) return null

  return (
    <div className="grid gap-2">
      {OAUTH_PROVIDER_ORDER.filter((provider) => oauthProviders.includes(provider)).map((provider) => (
        <Button
          key={provider}
          type="button"
          variant="outline"
          className="w-full"
          disabled={isLoading}
          onClick={() => onClick(provider)}
        >
          <span className="mr-2">{PROVIDER_ICONS[provider]}</span>
          {PROVIDER_LABELS[provider]}
        </Button>
      ))}
    </div>
  )
}

export function AuthErrorAlert({ error }: { error: string }) {
  if (!error) return null
  return (
    <Alert variant={error.includes('successful') ? 'default' : 'destructive'}>
      <AlertDescription>{error}</AlertDescription>
    </Alert>
  )
}

export function isTotpSubmitDisabled(isLoading: boolean, totpCode: string) {
  return isLoading || !isValidTotpOrRecoveryCode(totpCode)
}

export function PasskeyButton({ isLoading, onClick }: { isLoading: boolean; onClick: () => void }) {
  return (
    <Button type="button" variant="outline" className="w-full" disabled={isLoading} onClick={onClick}>
      <Fingerprint className="mr-2 h-4 w-4" />
      Sign in with a passkey
    </Button>
  )
}
