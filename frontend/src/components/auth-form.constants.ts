export const OAUTH_PROVIDER_ORDER = ['google', 'github', 'discord'] as const;

export const OAUTH_ERROR_MESSAGES: Record<string, string> = {
  oauth_denied: 'OAuth authorization was cancelled.',
  oauth_missing_params: 'OAuth response was incomplete. Please try again.',
  invalid_provider: 'Invalid OAuth provider.',
  oauth_state_missing: 'OAuth session expired. Please try again.',
  oauth_state_invalid: 'OAuth session was invalid. Please try again.',
  oauth_state_mismatch: 'OAuth state mismatch. Please try again.',
  oauth_exchange_failed: 'Failed to complete OAuth sign-in. Please try again.',
  oauth_email_not_verified: 'Your email is not verified with this provider. Please verify it first.',
  oauth_email_taken: 'An account with this email already exists. Please log in with your password, then link this provider from Settings.',
  oauth_user_not_found: 'Associated account not found.',
  oauth_already_linked_other: 'This social account is already linked to another user.',
  pending_approval: 'Your account is awaiting admin approval.',
  account_restricted: 'Your account has been suspended.',
  oauth_no_account: 'No account found with this email. Please register first.',
  rate_limited: 'Too many attempts. Please try again in a moment.',
  docs_auth_required: 'Please log in to access the API documentation.',
  oauth_server_error: 'An unexpected error occurred. Please try again.',
};
