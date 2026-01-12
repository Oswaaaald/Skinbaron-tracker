import { useState } from 'react';

/**
 * Form sections for managing separate error/success states
 */
export type FormSection = 'profile' | 'password' | 'twoFactor' | 'general';

/**
 * State for a single form section
 */
interface SectionState {
  error: string;
  success: string;
}

/**
 * Complete form state with all sections
 */
type FormState = Record<FormSection, SectionState>;

/**
 * Hook for managing form error and success messages across multiple sections
 * 
 * @example
 * ```tsx
 * const { state, setError, setSuccess, clear, clearAll } = useFormState();
 * 
 * // Set an error for a specific section
 * setError('profile', 'Username is required');
 * 
 * // Set success message
 * setSuccess('password', 'Password updated successfully');
 * 
 * // Clear specific section
 * clear('profile');
 * 
 * // Display error/success
 * {state.profile.error && <Alert variant="destructive">{state.profile.error}</Alert>}
 * {state.profile.success && <Alert>{state.profile.success}</Alert>}
 * ```
 */
export function useFormState() {
  const [state, setState] = useState<FormState>({
    profile: { error: '', success: '' },
    password: { error: '', success: '' },
    twoFactor: { error: '', success: '' },
    general: { error: '', success: '' },
  });

  /**
   * Set an error message for a specific section
   * Automatically clears any success message for that section
   */
  const setError = (section: FormSection, message: string) => {
    setState(prev => ({
      ...prev,
      [section]: { error: message, success: '' }
    }));
  };

  /**
   * Set a success message for a specific section
   * Automatically clears any error message for that section
   */
  const setSuccess = (section: FormSection, message: string) => {
    setState(prev => ({
      ...prev,
      [section]: { success: message, error: '' }
    }));
  };

  /**
   * Clear both error and success messages for a specific section
   */
  const clear = (section: FormSection) => {
    setState(prev => ({
      ...prev,
      [section]: { error: '', success: '' }
    }));
  };

  /**
   * Clear all error and success messages for all sections
   */
  const clearAll = () => {
    setState({
      profile: { error: '', success: '' },
      password: { error: '', success: '' },
      twoFactor: { error: '', success: '' },
      general: { error: '', success: '' },
    });
  };

  return {
    state,
    setError,
    setSuccess,
    clear,
    clearAll,
  };
}
