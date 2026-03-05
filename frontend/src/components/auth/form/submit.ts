import { formatDateTime } from '@/lib/formatters'
import { PASSWORD_RULES } from '@skinbaron/contracts'
import type { AuthFormData, AuthMode } from '@/components/auth/form/types'

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

function validateEmailShape(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

function validateUsernameShape(username: string): string | null {
  if (!username || username.trim().length === 0) {
    return 'Username is required'
  }

  if (username.length < 3 || username.length > 20) {
    return 'Username must be between 3 and 20 characters'
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return 'Username can only contain letters, numbers and underscores'
  }

  return null
}

/**
 * Keep heavy password-strength scoring (zxcvbn) out of the initial auth bundle.
 * We only load it when user submits a registration form.
 */
async function validateRegistrationForm(formData: AuthFormData): Promise<string | null> {
  const usernameError = validateUsernameShape(formData.username)
  if (usernameError) return usernameError

  if (!formData.email || formData.email.trim().length === 0) {
    return 'Email is required'
  }
  if (!validateEmailShape(formData.email)) {
    return 'Please enter a valid email address'
  }

  if (!formData.password || formData.password.length === 0) {
    return 'Password is required'
  }
  if (formData.password.length < PASSWORD_RULES.minLength) {
    return `Password must be at least ${PASSWORD_RULES.minLength} characters`
  }
  if (formData.password.length > PASSWORD_RULES.maxLength) {
    return `Password must be at most ${PASSWORD_RULES.maxLength} characters`
  }
  if (!PASSWORD_RULES.complexityRegex.test(formData.password)) {
    return PASSWORD_RULES.complexityMessage
  }

  const { default: zxcvbn } = await import('zxcvbn')
  if (zxcvbn(formData.password).score < 3) {
    return PASSWORD_RULES.weakPasswordMessage
  }

  if (formData.password !== formData.confirmPassword) {
    return 'Passwords do not match'
  }

  if (!formData.tosAccepted) {
    return 'You must accept the Terms of Service to create an account'
  }

  return null
}

export async function validateAuthForm(mode: AuthMode, formData: AuthFormData): Promise<string | null> {
  if (mode === 'register') {
    return validateRegistrationForm(formData)
  }

  if (!formData.email || !formData.password) {
    return 'Email and password are required'
  }
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
