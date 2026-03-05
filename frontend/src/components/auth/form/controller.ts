'use client'

import { useEffect, useState, type FormEvent, type KeyboardEvent } from 'react'
import { startAuthentication } from '@simplewebauthn/browser'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/auth-context'
import { queueToast, useToast } from '@/hooks/use-toast'
import { apiClient } from '@/lib/api'
import { OAUTH_ERROR_MESSAGES } from '@/components/auth/form/constants'
import {
  getOAuthUsernameValidationError,
  isValidTotpOrRecoveryCode,
} from '@/components/auth/form/helpers'
import { submitPrimaryAuth, validateAuthForm } from '@/components/auth/form/submit'
import type { AuthFormData, AuthMode, OAuthPendingData } from '@/components/auth/form/types'

export function useAuthFormController(mode: AuthMode, onToggleMode: () => void) {
  const { login, register } = useAuth()
  const router = useRouter()
  const { toast } = useToast()

  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [requires2FA, setRequires2FA] = useState(false)
  const [oauthPending2FA, setOauthPending2FA] = useState(false)
  const [oauthPendingRegistration, setOauthPendingRegistration] = useState(false)
  const [oauthPendingData, setOauthPendingData] = useState<OAuthPendingData | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [oauthProviders, setOAuthProviders] = useState<string[]>([])
  const [oauthReady, setOauthReady] = useState(false)
  const [formData, setFormData] = useState<AuthFormData>({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    tosAccepted: false,
  })

  useEffect(() => {
    void (async () => {
      try {
        const res = await apiClient.getOAuthProviders()
        if (res.success && res.data?.providers) setOAuthProviders(res.data.providers)
      } catch {
        // OAuth unavailable: buttons hidden silently
      } finally {
        setOauthReady(true)
      }
    })()
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return

    const params = new URLSearchParams(window.location.search)
    const oauth2fa = params.get('oauth_2fa')
    if (oauth2fa === 'pending') {
      setOauthPending2FA(true)
      const url = new URL(window.location.href)
      url.searchParams.delete('oauth_2fa')
      window.history.replaceState({}, '', url.pathname + url.search)
      return
    }

    const oauthFinalize = params.get('oauth_finalize')
    if (oauthFinalize === 'pending') {
      const url = new URL(window.location.href)
      url.searchParams.delete('oauth_finalize')
      window.history.replaceState({}, '', url.pathname + url.search)

      void (async () => {
        try {
          const res = await apiClient.getOAuthPendingRegistration()
          if (res.success && res.data) {
            setOauthPendingRegistration(true)
            setOauthPendingData(res.data)
            setFormData((prev) => ({
              ...prev,
              username: res.data?.suggested_username ?? '',
              email: res.data?.email ?? '',
              tosAccepted: false,
            }))
          } else {
            setError('OAuth registration session expired. Please try again.')
          }
        } catch {
          setError('OAuth registration session expired. Please try again.')
        }
      })()
      return
    }

    const oauthError = params.get('error')
    if (oauthError) {
      setError(OAUTH_ERROR_MESSAGES[oauthError] || 'OAuth sign-in failed. Please try again.')
      const url = new URL(window.location.href)
      url.searchParams.delete('error')
      window.history.replaceState({}, '', url.pathname + url.search)
    }
  }, [])

  const isLogin = mode === 'login'

  const setField = (field: keyof AuthFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    if (error) setError('')
  }

  const setTosAccepted = (checked: boolean) => {
    setFormData((prev) => ({ ...prev, tosAccepted: checked }))
    if (error) setError('')
  }

  const validateForm = () => {
    const validationError = validateAuthForm(mode, formData)
    if (!validationError) return true
    setError(validationError)
    return false
  }

  const completeSessionAndRedirect = (title: string, description: string) => {
    if (typeof window !== 'undefined') localStorage.setItem('has_session', 'true')
    queueToast({ title, description })
    router.replace('/alerts')
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()

    if (oauthPendingRegistration) {
      const oauthUsernameError = getOAuthUsernameValidationError(formData.username)
      if (oauthUsernameError) return setError(oauthUsernameError)
      if (!formData.tosAccepted) return setError('You must accept the Terms of Service to create an account')

      setIsLoading(true)
      setError('')
      try {
        const result = await apiClient.finalizeOAuthRegistration(formData.username.trim(), formData.tosAccepted)
        if (result.success) completeSessionAndRedirect('✅ Account created', 'Your account has been created successfully')
        else setError(result.message || 'Registration failed. Please try again.')
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }

    if (oauthPending2FA) {
      if (!isValidTotpOrRecoveryCode(totpCode)) {
        setError('Please enter a valid 6-digit code or 8-character recovery code')
        return
      }
      setIsLoading(true)
      setError('')
      try {
        const result = await apiClient.verifyOAuth2FA(totpCode)
        if (result.success) completeSessionAndRedirect('✅ Welcome back!', 'You have been logged in successfully')
        else {
          setError(result.message || 'Invalid 2FA code')
          setTotpCode('')
        }
      } catch {
        setError('An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }

    if (requires2FA) {
      if (!isValidTotpOrRecoveryCode(totpCode)) return setError('Please enter a valid 6-digit code or 8-character recovery code')
      setIsLoading(true)
      setError('')
      try {
        const result = await login(formData.email, formData.password, totpCode)
        if (result.success) {
          completeSessionAndRedirect('✅ Welcome back!', 'You have been logged in successfully')
        } else {
          setError(result.error || 'Invalid 2FA code')
          setTotpCode('')
        }
      } catch {
        setError('An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }

    if (!validateForm()) return

    setIsLoading(true)
    setError('')
    try {
      await submitPrimaryAuth({
        mode,
        formData,
        login: (email, password) => login(email, password),
        register: (username, email, password) => register(username, email, password),
        onRequires2FA: () => {
          setRequires2FA(true)
          setError('')
        },
        onError: (message) => {
          setError(message)
          toast({
            variant: 'destructive',
            title: `❌ ${mode === 'login' ? 'Login' : 'Registration'} failed`,
            description: message,
          })
        },
        onPendingApproval: () => {
          setError('Your account is awaiting admin approval. Please check back later.')
          toast({ variant: 'destructive', title: '❌ Account pending', description: 'Your account is awaiting admin approval' })
        },
        onSuccessLogin: () => {
          completeSessionAndRedirect('✅ Welcome back!', 'You have been logged in successfully')
        },
        onSuccessRegister: () => {
          completeSessionAndRedirect('✅ Account created', 'Your account has been created successfully')
        },
        onSuccessRegisterPendingApproval: () => {
          setError('Registration successful! Your account is awaiting admin approval.')
          toast({ title: '✅ Account created', description: 'Your account is awaiting admin approval' })
          setTimeout(onToggleMode, 2000)
        },
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'An unexpected error occurred. Please try again.'
      setError(message)
      toast({ variant: 'destructive', title: '❌ Error', description: message })
    } finally {
      setIsLoading(false)
    }
  }

  const handlePasskeyLogin = async () => {
    setError('')
    setIsLoading(true)
    try {
      const optionsRes = await apiClient.getPasskeyAuthOptions()
      if (!optionsRes.success || !optionsRes.data) return setError(optionsRes.message || 'Failed to start passkey authentication')

      const { challengeKey, ...publicKeyOptions } = optionsRes.data
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      const assertion = await startAuthentication({ optionsJSON: publicKeyOptions as any })
      const verifyRes = await apiClient.verifyPasskeyAuth(assertion, challengeKey)

      if (verifyRes.success && verifyRes.data) {
        completeSessionAndRedirect('✅ Welcome back!', 'Signed in with passkey')
      } else {
        setError(verifyRes.message || 'Passkey authentication failed')
      }
    } catch (err: unknown) {
      if (err instanceof Error && (err.name === 'NotAllowedError' || err.name === 'AbortError')) return
      setError(err instanceof Error ? err.message : 'Passkey authentication failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDownSubmit = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key !== 'Enter') return
    e.preventDefault()
    if (isLoading) return
    if (!requires2FA && !oauthPending2FA && !isLogin && !formData.tosAccepted) return
    if ((requires2FA || oauthPending2FA) && !isValidTotpOrRecoveryCode(totpCode)) return
    void handleSubmit(e as unknown as FormEvent)
  }

  return {
    isLoading,
    error,
    showPassword,
    requires2FA,
    oauthPending2FA,
    oauthPendingRegistration,
    oauthPendingData,
    totpCode,
    oauthProviders,
    oauthReady,
    formData,
    isLogin,
    setShowPassword,
    setRequires2FA,
    setOauthPending2FA,
    setOauthPendingRegistration,
    setOauthPendingData,
    setTotpCode,
    setFormData,
    setError,
    setField,
    setTosAccepted,
    handleSubmit,
    handlePasskeyLogin,
    handleKeyDownSubmit,
  }
}
