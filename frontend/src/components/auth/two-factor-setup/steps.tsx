import { DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingState } from '@/components/ui/loading-state'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { AlertCircle, CheckCircle, Copy } from 'lucide-react'

type SetupData = { secret: string; qrCode?: string; recovery_codes?: string[] }

export function TwoFactorQrStep({
  setupLoading,
  setupData,
  secret,
  copiedSecret,
  onCopySecret,
  onNext,
}: {
  setupLoading: boolean
  setupData?: SetupData
  secret: string
  copiedSecret: boolean
  onCopySecret: () => void
  onNext: () => void
}) {
  return (
    <div className="space-y-4">
      {setupLoading ? (
        <LoadingState variant="inline" />
      ) : setupData ? (
        <>
          <div className="flex justify-center p-4 bg-card border rounded-lg">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={setupData.qrCode}
              alt="2FA QR Code"
              width={200}
              height={200}
              className="rounded"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="manual-entry-key">Manual Entry Key</Label>
            <div className="flex gap-2">
              <Input id="manual-entry-key" value={secret} readOnly className="font-mono text-sm" />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={onCopySecret}
                aria-label="Copy secret key"
              >
                {copiedSecret ? (
                  <CheckCircle className="h-4 w-4 text-primary" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">Use this key if you can&apos;t scan the QR code</p>
          </div>

          <Alert>
            <AlertDescription className="text-sm">
              <strong>Supported apps:</strong> Google Authenticator, Authy, 1Password, Bitwarden
            </AlertDescription>
          </Alert>
        </>
      ) : null}

      <DialogFooter>
        <Button onClick={onNext} disabled={setupLoading}>Next</Button>
      </DialogFooter>
    </div>
  )
}

export function TwoFactorVerifyStep({
  verificationCode,
  isPending,
  onBack,
  onVerify,
  onCodeChange,
}: {
  verificationCode: string
  isPending: boolean
  onBack: () => void
  onVerify: () => void
  onCodeChange: (value: string) => void
}) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="code">Verification Code</Label>
        <Input
          id="code"
          placeholder="000000"
          value={verificationCode}
          onChange={(e) => onCodeChange(e.target.value.replace(/\D/g, '').slice(0, 6))}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && verificationCode.length === 6 && !isPending) {
              e.preventDefault()
              onVerify()
            }
          }}
          maxLength={6}
          className="text-center text-2xl tracking-widest font-mono"
          autoFocus
        />
        <p className="text-xs text-muted-foreground text-center">
          Enter the 6-digit code from your authenticator app
        </p>
      </div>

      <DialogFooter className="gap-2">
        <Button variant="outline" onClick={onBack}>Back</Button>
        <Button onClick={onVerify} disabled={isPending || verificationCode.length !== 6}>
          {isPending ? (
            <>
              <LoadingSpinner size="sm" className="mr-2" inline />
              Verifying...
            </>
          ) : (
            'Verify & Enable'
          )}
        </Button>
      </DialogFooter>
    </div>
  )
}

export function TwoFactorRecoveryCodesStep({
  recoveryCodes,
  copiedCodes,
  onCopyRecoveryCodes,
  onDone,
}: {
  recoveryCodes: string[]
  copiedCodes: boolean
  onCopyRecoveryCodes: () => void
  onDone: () => void
}) {
  return (
    <div className="space-y-4">
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          <strong>Important:</strong> Save these codes in a safe place. You&apos;ll need them to access your account if you lose your authenticator.
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Recovery Codes</Label>
          <Button type="button" variant="outline" size="sm" onClick={onCopyRecoveryCodes}>
            {copiedCodes ? (
              <>
                <CheckCircle className="h-4 w-4 mr-2 text-primary" />
                Copied!
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 mr-2" />
                Copy All
              </>
            )}
          </Button>
        </div>
        <div className="grid grid-cols-2 gap-2 p-4 bg-muted rounded-lg font-mono text-sm">
          {recoveryCodes.map((code, index) => (
            <div key={index} className="text-center">{code}</div>
          ))}
        </div>
      </div>

      <Alert className="border-primary/50 bg-primary/10">
        <CheckCircle className="h-4 w-4 text-primary" />
        <AlertDescription className="text-primary">
          Two-factor authentication has been enabled successfully!
        </AlertDescription>
      </Alert>

      <DialogFooter>
        <Button onClick={onDone} className="w-full">Done</Button>
      </DialogFooter>
    </div>
  )
}
