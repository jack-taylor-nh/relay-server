/**
 * Auth Routes
 * 
 * POST /v1/auth/nonce - Request a nonce for authentication
 * POST /v1/auth/verify - Verify signature and get session token
 */

import { Hono } from 'hono';
import { eq, and, gt } from 'drizzle-orm';
import { db, authNonces, identities } from '../db';
import { generateNonce as generateCryptoNonce, verifyString, fromBase64, computeFingerprint } from '../core/crypto';
import { NONCE_TTL_SECONDS, SESSION_TOKEN_TTL_SECONDS } from '../core/constants';
import { signSessionToken } from '../lib/jwt';

export const authRoutes = new Hono();

/**
 * Request a nonce for authentication
 */
authRoutes.post('/nonce', async (c) => {
  const body = await c.req.json<{ identityId: string }>();
  
  if (!body.identityId) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'identityId is required' }, 400);
  }

  // Generate nonce
  const nonce = generateCryptoNonce();
  const expiresAt = new Date(Date.now() + NONCE_TTL_SECONDS * 1000);

  // Store nonce
  await db.insert(authNonces).values({
    nonce,
    identityId: body.identityId,
    expiresAt,
  });

  return c.json({
    nonce,
    expiresAt: expiresAt.toISOString(),
  });
});

/**
 * Verify signature and return session token
 */
authRoutes.post('/verify', async (c) => {
  const body = await c.req.json<{
    publicKey: string;
    nonce: string;
    signature: string;
  }>();

  if (!body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Compute identity ID from public key
  const publicKey = fromBase64(body.publicKey);
  const identityId = computeFingerprint(publicKey);

  // Find and validate nonce
  const [storedNonce] = await db
    .select()
    .from(authNonces)
    .where(
      and(
        eq(authNonces.nonce, body.nonce),
        eq(authNonces.identityId, identityId),
        gt(authNonces.expiresAt, new Date())
      )
    )
    .limit(1);

  if (!storedNonce) {
    return c.json({ code: 'NONCE_EXPIRED', message: 'Nonce is invalid or expired' }, 401);
  }

  // Verify signature
  const messageToSign = `relay-auth:${body.nonce}`;
  
  const isValid = verifyString(messageToSign, body.signature, publicKey);
  
  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  // Delete used nonce
  await db.delete(authNonces).where(eq(authNonces.nonce, body.nonce));

  // Update identity last seen
  await db
    .update(identities)
    .set({ lastSeenAt: new Date() })
    .where(eq(identities.id, identityId));

  // Generate session token
  const expiresAt = new Date(Date.now() + SESSION_TOKEN_TTL_SECONDS * 1000);
  const token = await signSessionToken({
    fingerprint: identityId, // fingerprint === identityId
    exp: Math.floor(expiresAt.getTime() / 1000),
  });

  return c.json({
    token,
    identityId,
    expiresAt: expiresAt.toISOString(),
  });
});
