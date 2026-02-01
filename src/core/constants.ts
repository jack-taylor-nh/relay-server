/**
 * Relay Protocol Constants
 */

// Handle format: &name (3-24 chars, lowercase alphanumeric + underscores)
export const HANDLE_PREFIX = '&';
export const HANDLE_MIN_LENGTH = 3;
export const HANDLE_MAX_LENGTH = 24;
export const HANDLE_PATTERN = /^[a-z][a-z0-9_]{2,23}$/;

// Reserved handles
export const RESERVED_HANDLES = [
  'admin',
  'relay',
  'support',
  'help',
  'system',
  'security',
  'abuse',
  'postmaster',
  'root',
  'null',
  'undefined',
  'api',
  'www',
  'mail',
  'email',
] as const;

// Crypto
export const NONCE_BYTES = 24;
export const KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;
export const PUBKEY_BYTES = 32;

// Session
export const SESSION_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
export const NONCE_TTL_SECONDS = 60 * 5; // 5 minutes

// Rate limits
export const RATE_LIMIT_MESSAGES_PER_MINUTE = 30;
export const RATE_LIMIT_ALIAS_CREATES_PER_DAY = 10;

// Pagination
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;
