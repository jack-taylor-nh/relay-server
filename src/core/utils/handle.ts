/**
 * Handle validation utilities
 */

import { HANDLE_PATTERN, HANDLE_MIN_LENGTH, HANDLE_MAX_LENGTH, RESERVED_HANDLES } from '../constants';

export interface HandleValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate a handle string
 */
export function validateHandle(handle: string): HandleValidationResult {
  // Remove & prefix if present
  const cleanHandle = handle.startsWith('&') ? handle.slice(1) : handle;
  
  if (cleanHandle.length < HANDLE_MIN_LENGTH) {
    return {
      valid: false,
      error: `Handle must be at least ${HANDLE_MIN_LENGTH} characters`,
    };
  }
  
  if (cleanHandle.length > HANDLE_MAX_LENGTH) {
    return {
      valid: false,
      error: `Handle must be at most ${HANDLE_MAX_LENGTH} characters`,
    };
  }
  
  if (!HANDLE_PATTERN.test(cleanHandle)) {
    return {
      valid: false,
      error: 'Handle must start with a letter and contain only lowercase letters, numbers, and underscores',
    };
  }
  
  if (RESERVED_HANDLES.includes(cleanHandle as typeof RESERVED_HANDLES[number])) {
    return {
      valid: false,
      error: 'This handle is reserved',
    };
  }
  
  return { valid: true };
}

/**
 * Normalize a handle (lowercase, strip & prefix)
 */
export function normalizeHandle(handle: string): string {
  return handle.toLowerCase().replace(/^&/, '');
}

/**
 * Format a handle with & prefix
 */
export function formatHandle(handle: string): string {
  const clean = normalizeHandle(handle);
  return `&${clean}`;
}
