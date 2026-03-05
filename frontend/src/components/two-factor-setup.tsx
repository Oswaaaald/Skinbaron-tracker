'use client'

import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertCircle, Shield } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import { QUERY_KEYS } from '@/lib/constants'
import {
  TwoFactorQrStep,
  TwoFactorVerifyStep,
  TwoFactorRecoveryCodesStep,
} from './two-factor-setup-steps'

interface TwoFactorSetupProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function TwoFactorSetup({ open, onOpenChange }: TwoFactorSetupProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [step, setStep] = useState<'qr' | 'verify' | 'codes'>('qr')
  const [verificationCode, setVerificationCode] = useState('')
  const [secret, setSecret] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [error, setError] = useState('')
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [copiedCodes, setCopiedCodes] = useState(false)

  const { data: setupData, isLoading: setupLoading } = useQuery({
    queryKey: [QUERY_KEYS.TWO_FA_SETUP],
    queryFn: async () => {
      const response = await apiClient.post('/api/user/2fa/setup')
      if (response.success && response.data) {
        const payload = response.data as { secret: string; qrCode?: string; recovery_codes?: string[] }
        setSecret(payload.secret)
        return payload
      }
      throw new Error('Failed to get 2FA setup')
    },
    enabled: open,
    staleTime: Infinity,
  })

  const enableMutation = useApiMutation(
    async () => {
      const response = await apiClient.post('/api/user/2fa/enable', {
        code: verificationCode,
      })
      if (!response.success) {
        throw new Error(response.error || 'Invalid verification code')
      }
      return response
    },
    {
      invalidateKeys: [[QUERY_KEYS.TWO_FA_STATUS]],
      onSuccess: (response) => {
        if (response.success && response.data) {
          const payload = response.data as { recovery_codes?: string[] }
          if (payload.recovery_codes) {
            setRecoveryCodes(payload.recovery_codes)
          }
          setStep('codes')
          setError('')
          toast({
            title: '✅ 2FA enabled',
            description: 'Two-factor authentication has been enabled successfully',
          })
        }
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : undefined
        const safeMessage = message || 'Invalid verification code'
        setError(safeMessage)
        toast({
          variant: 'destructive',
          title: '❌ Verification failed',
          description: safeMessage,
        })
      },
    },
  )

  const handleVerify = () => {
    if (verificationCode.length === 6 || verificationCode.length === 8) {
      enableMutation.mutate()
    } else {
      setError('Please enter a 6-digit code or 8-character recovery code')
    }
  }

  const resetDialogState = () => {
    setStep('qr')
    setVerificationCode('')
    setSecret('')
    setRecoveryCodes([])
    setError('')
    setCopiedSecret(false)
    setCopiedCodes(false)
  }

  const handleComplete = () => {
    onOpenChange(false)
    queryClient.removeQueries({ queryKey: [QUERY_KEYS.TWO_FA_SETUP] })
    setTimeout(resetDialogState, 200)
  }

  const copySecret = () => {
    void navigator.clipboard.writeText(secret)
    setCopiedSecret(true)
    setTimeout(() => setCopiedSecret(false), 2000)
  }

  const copyRecoveryCodes = () => {
    void navigator.clipboard.writeText(recoveryCodes.join('\n'))
    setCopiedCodes(true)
    setTimeout(() => setCopiedCodes(false), 2000)
  }

  const handleOpenChange = useCallback((newOpen: boolean) => {
    if (!newOpen && step === 'codes') return

    onOpenChange(newOpen)
    if (!newOpen) {
      queryClient.removeQueries({ queryKey: [QUERY_KEYS.TWO_FA_SETUP] })
      setTimeout(resetDialogState, 200)
    }
  }, [onOpenChange, queryClient, step])

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="sm:max-w-md"
        showCloseButton={step !== 'codes'}
        onInteractOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={step === 'codes' ? (e) => e.preventDefault() : undefined}
      >
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

        {step === 'qr' && (
          <TwoFactorQrStep
            setupLoading={setupLoading}
            setupData={setupData}
            secret={secret}
            copiedSecret={copiedSecret}
            onCopySecret={copySecret}
            onNext={() => setStep('verify')}
          />
        )}

        {step === 'verify' && (
          <TwoFactorVerifyStep
            verificationCode={verificationCode}
            isPending={enableMutation.isPending}
            onBack={() => setStep('qr')}
            onVerify={handleVerify}
            onCodeChange={setVerificationCode}
          />
        )}

        {step === 'codes' && (
          <TwoFactorRecoveryCodesStep
            recoveryCodes={recoveryCodes}
            copiedCodes={copiedCodes}
            onCopyRecoveryCodes={copyRecoveryCodes}
            onDone={handleComplete}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}
