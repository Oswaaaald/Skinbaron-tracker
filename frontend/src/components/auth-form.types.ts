export type AuthMode = 'login' | 'register'

export interface AuthFormData {
  username: string
  email: string
  password: string
  confirmPassword: string
  tosAccepted: boolean
}

export interface OAuthPendingData {
  email: string
  suggested_username: string
  provider: string
}
