'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { AlertCircle, CheckCircle, Copy, Shield } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'

interface TwoFactorSetupProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function TwoFactorSetup({ open, onOpenChange }: TwoFactorSetupProps) {
  const { toast } = useToast()
  const [step, setStep] = useState<'qr' | 'verify' | 'codes'>('qr')
  const [verificationCode, setVerificationCode] = useState('')
  const [secret, setSecret] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [error, setError] = useState('')
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [copiedCodes, setCopiedCodes] = useState(false)

  // Fetch 2FA setup
  const { data: setupData, isLoading: setupLoading } = useQuery({
    queryKey: ['2fa-setup'],
    queryFn: async () => {
      const response = await apiClient.post('/api/user/2fa/setup')
      if (response.success && response.data) {
        setSecret(response.data.secret)
        return response.data
      }
      throw new Error('Failed to get 2FA setup')
    },
    enabled: open && step === 'qr',
  })

  // Enable 2FA mutation
  const enableMutation = useApiMutation(
    async () => {
      const response = await apiClient.post('/api/user/2fa/enable', {
        secret,
        code: verificationCode,
      })
      if (!response.success) {
        throw new Error(response.error || 'Invalid verification code')
      }
      return response
    },
    {
      invalidateKeys: [['2fa-status']],
      onSuccess: (response) => {
        if (response.success && response.data?.recovery_codes) {
          setRecoveryCodes(response.data.recovery_codes)
          setStep('codes')
          setError('')
          toast({
            title: "✅ 2FA enabled",
            description: "Two-factor authentication has been enabled successfully",
          })
        }
      },
      onError: (error: any) => {
        setError(error.message || 'Invalid verification code')
        toast({
          variant: "destructive",
          title: "❌ Verification failed",
          description: error.message || 'Invalid verification code',
        })
      },
    }
  )

  const handleVerify = () => {
    if (verificationCode.length === 6 || verificationCode.length === 8) {
      enableMutation.mutate()
    } else {
      setError('Please enter a 6-digit code or 8-character recovery code')
    }
  }

  const handleComplete = () => {
    onOpenChange(false)
    setStep('qr')
    setVerificationCode('')
    setSecret('')
    setRecoveryCodes([])
    setError('')
  }

  const copySecret = () => {
    navigator.clipboard.writeText(secret)
    setCopiedSecret(true)
    setTimeout(() => setCopiedSecret(false), 2000)
  }

  const copyRecoveryCodes = () => {
    navigator.clipboard.writeText(recoveryCodes.join('\n'))
    setCopiedCodes(true)
    setTimeout(() => setCopiedCodes(false), 2000)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Enable Two-Factor Authentication
          </DialogTitle>
          <DialogDescription>
            {step === 'qr' && 'Scan the QR code with your authenticator app'}
            {step === 'verify' && 'Enter the 6-digit code from your app'}
            {step === 'codes' && 'Save your recovery codes in a safe place'}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Step 1: QR Code */}
        {step === 'qr' && (
          <div className="space-y-4">
            {setupLoading ? (
              <div className="flex justify-center py-8">
                <LoadingSpinner size="lg" />
              </div>
            ) : setupData ? (
              <>
                <div className="flex justify-center p-4 bg-white rounded-lg">
                  <img 
                    src={setupData.qrCode} 
                    alt="2FA QR Code" 
                    width={200} 
                    height={200}
                    className="rounded"
                  />
                </div>

                <div className="space-y-2">
                  <Label>Manual Entry Key</Label>
                  <div className="flex gap-2">
                    <Input value={secret} readOnly className="font-mono text-sm" />
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      onClick={copySecret}
                    >
                      {copiedSecret ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Use this key if you can't scan the QR code
                  </p>
                </div>

                <Alert>
                  <AlertDescription className="text-sm">
                    <strong>Supported apps:</strong> Google Authenticator, Authy, 1Password, Bitwarden
                  </AlertDescription>
                </Alert>
              </>
            ) : null}

            <DialogFooter>
              <Button onClick={() => setStep('verify')} disabled={setupLoading}>
                Next
              </Button>
            </DialogFooter>
          </div>
        )}

        {/* Step 2: Verification */}
        {step === 'verify' && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="code">Verification Code</Label>
              <Input
                id="code"
                placeholder="000000"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase().slice(0, 8))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && (verificationCode.length === 6 || verificationCode.length === 8) && !enableMutation.isPending) {
                    e.preventDefault()
                    handleVerify()
                  }
                }}
                maxLength={8}
                className="text-center text-2xl tracking-widest font-mono"
                autoFocus
              />
              <p className="text-xs text-muted-foreground text-center">
                Enter the 6-digit code from your authenticator app or an 8-character recovery code
              </p>
            </div>

            <DialogFooter className="gap-2">
              <Button variant="outline" onClick={() => setStep('qr')}>
                Back
              </Button>
              <Button
                onClick={handleVerify}
                disabled={enableMutation.isPending || (verificationCode.length !== 6 && verificationCode.length !== 8)}
              >
                {enableMutation.isPending ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-2" />
                    Verifying...
                  </>
                ) : (
                  'Verify & Enable'
                )}
              </Button>
            </DialogFooter>
          </div>
        )}

        {/* Step 3: Recovery Codes */}
        {step === 'codes' && (
          <div className="space-y-4">
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Important:</strong> Save these codes in a safe place. You'll need them to access your account if you lose your authenticator.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Recovery Codes</Label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={copyRecoveryCodes}
                >
                  {copiedCodes ? (
                    <>
                      <CheckCircle className="h-4 w-4 mr-2 text-green-500" />
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
                  <div key={index} className="text-center">
                    {code}
                  </div>
                ))}
              </div>
            </div>

            <Alert>
              <CheckCircle className="h-4 w-4 text-green-500" />
              <AlertDescription className="text-green-600 dark:text-green-400">
                Two-factor authentication has been enabled successfully!
              </AlertDescription>
            </Alert>

            <DialogFooter>
              <Button onClick={handleComplete} className="w-full">
                Done
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
