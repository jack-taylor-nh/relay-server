/**
 * Identity Routes
 * 
 * POST /v1/identity/register - Register an identity
 * GET /v1/identity/:id - Get identity details
 */

import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db, identities, edges } from '../db/index.js';
import { verifyString, fromBase64, computeFingerprint } from '../core/crypto/index.js';

export const identityRoutes = new Hono();

/** Default home server for this instance */
const DEFAULT_HOME_SERVER = 'userelay.org';

/**
 * Register a new identity
 */
identityRoutes.post('/register', async (c) => {
  const body = await c.req.json<{
    publicKey: string;
    nonce: string;
    signature: string;
    homeServer?: string;
  }>();

  if (!body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Validate home server if provided (must be a valid domain)
  const homeServer = body.homeServer || DEFAULT_HOME_SERVER;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$/.test(homeServer)) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Invalid home server domain' }, 400);
  }

  // Verify signature (proves ownership of private key)
  const publicKey = fromBase64(body.publicKey);
  const messageToSign = `relay-register:${body.nonce}`;
  
  const isValid = verifyString(messageToSign, body.signature, publicKey);
  
  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  // Compute fingerprint (this is the identity ID)
  const fingerprint = computeFingerprint(publicKey);

  // Check if identity already exists
  const existing = await db
    .select()
    .from(identities)
    .where(eq(identities.id, fingerprint))
    .limit(1);

  if (existing.length > 0) {
    // Identity already registered - just return success
    return c.json({
      id: fingerprint,
      publicKey: body.publicKey,
      homeServer: existing[0].homeServer,
      status: existing[0].status,
      createdAt: existing[0].createdAt.toISOString(),
      isNew: false,
    }, 200);
  }

  // Register new identity
  const now = new Date();
  await db.insert(identities).values({
    id: fingerprint,
    publicKey: body.publicKey,
    homeServer,
    status: 'active',
    createdAt: now,
    lastSeenAt: now,
  });

  // NOTE: Native edges are now created when user claims a handle via /v1/edge endpoint
  // This auto-creation was creating phantom edges without x25519 keys, causing encryption failures
  // Legacy code removed - native edges must be explicitly created with x25519PublicKey
  const nativeEdgeId = null; // No longer auto-created

  return c.json({
    id: fingerprint,
    publicKey: body.publicKey,
    homeServer,
    status: 'active',
    nativeEdgeId,
    createdAt: now.toISOString(),
    isNew: true,
  }, 201);
});

/**
 * Get identity details
 * 
 * SECURITY: This endpoint only returns PUBLIC information about an identity.
 * It does NOT expose handles, edges, or any linkable data.
 * The only purpose is to verify an identity's public key for cryptographic operations.
 */
identityRoutes.get('/:id', async (c) => {
  const id = c.req.param('id');

  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.id, id))
    .limit(1);

  if (!identity) {
    return c.json({ code: 'IDENTITY_NOT_FOUND', message: 'Identity not found' }, 404);
  }

  // SECURITY: Only return minimal public info
  // Do NOT expose handles, edges, or any linkable data
  // Handles and edges are accessed via their respective endpoints with proper auth
  return c.json({
    id: identity.id,
    publicKey: identity.publicKey,
    homeServer: identity.homeServer,
    // Note: status, handles, edges intentionally NOT returned
    // Clients should query edges via the edges endpoint with their own auth
  });
});
