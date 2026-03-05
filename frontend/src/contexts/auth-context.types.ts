export interface User {
  id: number
  username: string
  email: string
  avatar_url?: string
  use_gravatar?: boolean
  is_admin?: boolean
  is_super_admin?: boolean
  has_password?: boolean
}

export interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  isReady: boolean
  login: (email: string, password: string, totpCode?: string) => Promise<{ success: boolean; error?: string; requires2FA?: boolean; restrictionExpiresAt?: string }>
  register: (username: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>
  logout: () => Promise<void>
  updateUser: (userData: Partial<User>) => void
}

export type InitialAuthState = {
  user: User
  token: string
  refreshToken: string | null
  expiresAt: number | null
  refreshExpiresAt: number | null
}
