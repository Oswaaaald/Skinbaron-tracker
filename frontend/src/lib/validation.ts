/**
 * Centralized validation rules
 * These must match backend validation schemas exactly (backend/src/lib/auth.ts)
 */

export type ValidationResult = {
  valid: boolean
  error?: string
}

/**
 * Username validation (3-20 chars, alphanumeric + underscore only)
 */
export function validateUsername(username: string): ValidationResult {
  if (!username || username.trim().length === 0) {
    return { valid: false, error: 'Username is required' }
  }

  if (username.length < 3 || username.length > 20) {
    return { valid: false, error: 'Username must be between 3 and 20 characters' }
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, error: 'Username can only contain letters, numbers and underscores' }
  }

  return { valid: true }
}

/**
 * Email validation
 */
export function validateEmail(email: string): ValidationResult {
  if (!email || email.trim().length === 0) {
    return { valid: false, error: 'Email is required' }
  }

  // Basic email regex (browser native validation is also used)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Please enter a valid email address' }
  }

  return { valid: true }
}

/**
 * Password validation (8+ chars, must contain uppercase, lowercase, and number)
 */
export function validatePassword(password: string): ValidationResult {
  if (!password || password.length === 0) {
    return { valid: false, error: 'Password is required' }
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' }
  }

  // Must contain at least one lowercase, one uppercase, and one digit
  if (!/(?=.*[a-z])/.test(password)) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' }
  }

  if (!/(?=.*[A-Z])/.test(password)) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' }
  }

  if (!/(?=.*\d)/.test(password)) {
    return { valid: false, error: 'Password must contain at least one number' }
  }

  return { valid: true }
}

/**
 * Password confirmation validation
 */
export function validatePasswordMatch(password: string, confirmPassword: string): ValidationResult {
  if (password !== confirmPassword) {
    return { valid: false, error: 'Passwords do not match' }
  }

  return { valid: true }
}

/**
 * Validate registration form
 */
export function validateRegistration(data: {
  username: string
  email: string
  password: string
  confirmPassword: string
}): ValidationResult {
  // Validate username
  const usernameResult = validateUsername(data.username)
  if (!usernameResult.valid) return usernameResult

  // Validate email
  const emailResult = validateEmail(data.email)
  if (!emailResult.valid) return emailResult

  // Validate password
  const passwordResult = validatePassword(data.password)
  if (!passwordResult.valid) return passwordResult

  // Validate password match
  const matchResult = validatePasswordMatch(data.password, data.confirmPassword)
  if (!matchResult.valid) return matchResult

  return { valid: true }
}

/**
 * Validate login form
 */
export function validateLogin(data: { email: string; password: string }): ValidationResult {
  if (!data.email || !data.password) {
    return { valid: false, error: 'Email and password are required' }
  }

  // For login, we don't validate format strictly (user might have old account)
  // Just check they provided something
  return { valid: true }
}

/**
 * Validate password change
 */
export function validatePasswordChange(data: {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}): ValidationResult {
  if (!data.currentPassword) {
    return { valid: false, error: 'Current password is required' }
  }

  // Validate new password
  const passwordResult = validatePassword(data.newPassword)
  if (!passwordResult.valid) return passwordResult

  // Validate password match
  const matchResult = validatePasswordMatch(data.newPassword, data.confirmPassword)
  if (!matchResult.valid) return matchResult

  return { valid: true }
}

/**
 * Validate set password (for OAuth-only users without an existing password)
 */
export function validateSetPassword(data: {
  newPassword: string
  confirmPassword: string
}): ValidationResult {
  // Validate new password
  const passwordResult = validatePassword(data.newPassword)
  if (!passwordResult.valid) return passwordResult

  // Validate password match
  const matchResult2 = validatePasswordMatch(data.newPassword, data.confirmPassword)
  if (!matchResult2.valid) return matchResult2

  return { valid: true }
}