import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Extract a user-friendly error message from any error type
 * Handles Error objects, API responses, and unknown error types
 * 
 * @param error - The error to extract a message from
 * @param fallback - Optional fallback message (default: "An unexpected error occurred")
 * @returns A user-friendly error message string
 */
export function extractErrorMessage(error: unknown, fallback: string = "An unexpected error occurred"): string {
  // Handle Error objects
  if (error instanceof Error) {
    return error.message;
  }
  
  // Handle API response objects with 'error' field
  if (typeof error === 'object' && error !== null) {
    // Check for 'error' property (common API pattern)
    if ('error' in error && typeof error.error === 'string') {
      return error.error;
    }
    
    // Check for 'message' property
    if ('message' in error && typeof error.message === 'string') {
      return error.message;
    }
    
    // Check for nested error object (e.g., { error: { message: '...' } })
    if ('error' in error && typeof error.error === 'object' && error.error !== null) {
      const nestedError = error.error;
      if ('message' in nestedError && typeof nestedError.message === 'string') {
        return nestedError.message;
      }
    }
  }
  
  // Handle string errors
  if (typeof error === 'string') {
    return error;
  }
  
  // Fallback
  return fallback;
}
