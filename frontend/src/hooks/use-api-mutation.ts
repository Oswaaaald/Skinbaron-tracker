import { useMutation, useQueryClient, UseMutationOptions } from '@tanstack/react-query';
import { toast } from 'sonner';

/**
 * Options for useApiMutation hook
 */
interface UseApiMutationOptions<TData, TVariables, TError = Error> {
  /**
   * Query keys to invalidate on success
   * Can be a single key or array of keys
   */
  invalidateKeys?: string[][] | string[];
  
  /**
   * Success message to display in toast
   */
  successMessage?: string;
  
  /**
   * Error message to display in toast (if not using onError callback)
   */
  errorMessage?: string;
  
  /**
   * Custom success callback
   */
  onSuccess?: (data: TData, variables: TVariables) => void;
  
  /**
   * Custom error callback
   */
  onError?: (error: TError, variables: TVariables) => void;
  
  /**
   * Additional mutation options from TanStack Query
   */
  mutationOptions?: Omit<UseMutationOptions<TData, TError, TVariables>, 'mutationFn' | 'onSuccess' | 'onError'>;
}

/**
 * Hook factory for API mutations with automatic query invalidation and toast notifications
 * 
 * @example
 * ```tsx
 * const updateProfileMutation = useApiMutation(
 *   (data) => apiClient.patch('/api/user/profile', data),
 *   {
 *     invalidateKeys: [['user', 'profile'], ['admin', 'users']],
 *     successMessage: 'Profile updated successfully',
 *     onSuccess: (data) => {
 *       updateUser(data);
 *     },
 *   }
 * );
 * 
 * // Use it
 * updateProfileMutation.mutate({ username: 'newname' });
 * ```
 */
export function useApiMutation<TData = unknown, TVariables = void, TError = Error>(
  mutationFn: (variables: TVariables) => Promise<TData>,
  options: UseApiMutationOptions<TData, TVariables, TError> = {}
) {
  const queryClient = useQueryClient();
  
  const {
    invalidateKeys = [],
    successMessage,
    errorMessage,
    onSuccess,
    onError,
    mutationOptions = {},
  } = options;

  return useMutation<TData, TError, TVariables>({
    mutationFn,
    onSuccess: (data, variables) => {
      // Invalidate queries
      const keysArray = Array.isArray(invalidateKeys[0]) 
        ? invalidateKeys as string[][]
        : [invalidateKeys as string[]];
      
      keysArray.forEach(key => {
        if (key.length > 0) {
          queryClient.invalidateQueries({ queryKey: key });
        }
      });
      
      // Show success toast
      if (successMessage) {
        toast.success(successMessage);
      }
      
      // Call custom success callback
      onSuccess?.(data, variables);
    },
    onError: (error, variables) => {
      // Show error toast if errorMessage provided and no custom error handler
      if (errorMessage && !onError) {
        toast.error(errorMessage);
      }
      
      // Call custom error callback
      onError?.(error, variables);
    },
    ...mutationOptions,
  });
}
