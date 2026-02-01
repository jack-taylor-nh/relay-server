/**
 * Edge Query Key Utilities
 * 
 * Implements zero-knowledge edge ownership using HMAC-based query keys.
 * Server can filter edges without knowing user identities.
 */

import { createHmac } from 'crypto';

/**
 * Server secret salt for query key generation.
 * CRITICAL SECURITY: Keep this secret! Rotate annually.
 * Store in environment variable, never commit to repo.
 */
function getServerSecretSalt(): string {
  const salt = process.env.EDGE_QUERY_KEY_SALT;
  if (!salt) {
    throw new Error('EDGE_QUERY_KEY_SALT environment variable not set');
  }
  if (salt.length < 32) {
    throw new Error('EDGE_QUERY_KEY_SALT must be at least 32 characters');
  }
  return salt;
}

/**
 * Compute query key for an identity.
 * 
 * Uses HMAC-SHA256 with server secret salt to create a one-way,
 * deterministic key that can be used to filter edges without
 * revealing the identity ID.
 * 
 * @param identityId - User's identity ID (fingerprint)
 * @returns Query key (hex string)
 */
export function computeQueryKey(identityId: string): string {
  const salt = getServerSecretSalt();
  return createHmac('sha256', salt)
    .update(identityId)
    .digest('hex');
}

/**
 * Verify a query key matches an identity ID.
 * Used for debugging/testing only - NOT for production queries.
 * 
 * @param queryKey - Query key to verify
 * @param identityId - Identity ID to check against
 * @returns True if query key matches identity
 */
export function verifyQueryKey(queryKey: string, identityId: string): boolean {
  return computeQueryKey(identityId) === queryKey;
}
