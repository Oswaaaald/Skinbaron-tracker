export function isValidTotpOrRecoveryCode(code: string): boolean {
  return code.length === 6 || code.length === 8;
}

export function sanitizeTotpInput(value: string): string {
  return value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
}

export function getOAuthUsernameValidationError(username: string): string | null {
  const normalized = username.trim();
  if (!normalized || normalized.length < 3) {
    return 'Username must be at least 3 characters';
  }
  if (normalized.length > 20) {
    return 'Username must be at most 20 characters';
  }
  if (!/^[a-zA-Z0-9_]+$/.test(normalized)) {
    return 'Username can only contain letters, numbers and underscores';
  }
  return null;
}
