import { formatDateTime } from '@/lib/formatters'
import { validateLogin, validateRegistration } from '@/lib/validation'
import type { AuthFormData, AuthMode } from '@/components/auth-form.types'

interface AuthResult {
  success: boolean
  error?: string
  requires2FA?: boolean
  restrictionExpiresAt?: string
}

interface SubmitPrimaryAuthParams {
  mode: AuthMode
  formData: AuthFormData
  login: (email: string, password: string) => Promise<AuthResult>
  register: (username: string, email: string, password: string) => Promise<AuthResult>
  onRequires2FA: () => void
  onError: (message: string) => void
  onPendingApproval: () => void
  onSuccessLogin: () => void
  onSuccessRegister: () => void
  onSuccessRegisterPendingApproval: () => void
}

export function validateAuthForm(mode: AuthMode, formData: AuthFormData): string | null {
  if (mode === 'register') {
    const result = validateRegistration({
      username: formData.username,
      email: formData.email,
      password: formData.password,
      confirmPassword: formData.confirmPassword,
    })
    if (!result.valid) return result.error || 'Validation failed'
    if (!formData.tosAccepted) return 'You must accept the Terms of Service to create an account'
    return null
  }

  const result = validateLogin({ email: formData.email, password: formData.password })
  if (!result.valid) return result.error || 'Validation failed'
  return null
}

export async function submitPrimaryAuth({
  mode,
  formData,
  login,
  register,
  onRequires2FA,
  onError,
  onPendingApproval,
  onSuccessLogin,
  onSuccessRegister,
  onSuccessRegisterPendingApproval,
}: SubmitPrimaryAuthParams) {
  const result: AuthResult = mode === 'login'
    ? await login(formData.email, formData.password)
    : await register(formData.username, formData.email, formData.password)

  if (result.success) {
    if (mode === 'login') onSuccessLogin()
    else if (result.error?.includes('awaiting admin approval')) onSuccessRegisterPendingApproval()
    else onSuccessRegister()
    return
  }

  if (result.requires2FA) {
    onRequires2FA()
    return
  }

  if (result.error === 'Account pending approval') {
    onPendingApproval()
    return
  }

  let errorMessage = result.error || `${mode} failed`
  if (result.restrictionExpiresAt) {
    errorMessage = `Your account is suspended until ${formatDateTime(result.restrictionExpiresAt)}`
  }
  onError(errorMessage)
}
