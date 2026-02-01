/**
 * Handle Routes
 * 
 * POST /v1/handle/claim - Claim a handle
 * GET /v1/handle/resolve - Resolve a handle to public key
 * DELETE /v1/handle/:name - Release a handle
 */

import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db, handles, identities } from '../db';
import { validateHandle, normalizeHandle, verifyString, fromBase64, computeFingerprint, initCrypto } from '@relay/core';

export const handleRoutes = new Hono();

/**
 * Claim a handle
 */
handleRoutes.post('/claim', async (c) => {
  await initCrypto();
  
  const body = await c.req.json<{
    handle: string;
    publicKey: string;
    nonce: string;
    signature: string;
  }>();

  if (!body.handle || !body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Validate handle format
  const normalizedHandle = normalizeHandle(body.handle);
  const validation = validateHandle(normalizedHandle);
  
  if (!validation.valid) {
    return c.json({ 
      code: 'HANDLE_INVALID', 
      message: validation.error,
    }, 400);
  }

  // Check if handle is already taken
  const existing = await db
    .select()
    .from(handles)
    .where(eq(handles.name, normalizedHandle))
    .limit(1);

  if (existing.length > 0) {
    return c.json({ code: 'HANDLE_TAKEN', message: 'This handle is already claimed' }, 409);
  }

  // Verify signature
  const publicKey = fromBase64(body.publicKey);
  const messageToSign = `relay-claim:${normalizedHandle}:${body.nonce}`;
  
  const isValid = verifyString(messageToSign, body.signature, publicKey);
  
  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  // Compute fingerprint (identity ID)
  const identityId = computeFingerprint(publicKey);

  // Ensure identity exists
  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.id, identityId))
    .limit(1);

  if (!identity) {
    return c.json({ code: 'IDENTITY_NOT_FOUND', message: 'Identity not registered. Register first.' }, 404);
  }

  // Check if this is the first handle for this identity
  const existingHandles = await db
    .select()
    .from(handles)
    .where(eq(handles.identityId, identityId));

  const isPrimary = existingHandles.length === 0;

  // Store handle
  await db.insert(handles).values({
    name: normalizedHandle,
    identityId,
    isPrimary,
    status: 'active',
  });

  return c.json({
    handle: normalizedHandle,
    identityId,
    isPrimary,
    claimedAt: new Date().toISOString(),
  }, 201);
});

/**
 * Release a handle (mark as disabled)
 */
handleRoutes.delete('/:name', async (c) => {
  await initCrypto();

  const handleName = normalizeHandle(c.req.param('name'));
  
  const body = await c.req.json<{
    publicKey: string;
    nonce: string;
    signature: string;
  }>();

  if (!body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Verify ownership
  const publicKey = fromBase64(body.publicKey);
  const messageToSign = `relay-release:${handleName}:${body.nonce}`;
  const isValid = verifyString(messageToSign, body.signature, publicKey);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(publicKey);

  // Find the handle and verify ownership
  const [handle] = await db
    .select()
    .from(handles)
    .where(eq(handles.name, handleName))
    .limit(1);

  if (!handle) {
    return c.json({ code: 'HANDLE_NOT_FOUND', message: 'Handle not found' }, 404);
  }

  if (handle.identityId !== identityId) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this handle' }, 403);
  }

  // Disable the handle
  await db
    .update(handles)
    .set({ status: 'disabled', disabledAt: new Date() })
    .where(eq(handles.name, handleName));

  return c.json({ message: 'Handle released', handle: handleName });
});

/**
 * Resolve a handle to public key
 */
handleRoutes.get('/resolve', async (c) => {
  const handleQuery = c.req.query('handle');
  
  if (!handleQuery) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'handle query parameter is required' }, 400);
  }

  const normalizedHandle = normalizeHandle(handleQuery);

  // Join handles with identities to get public key and home server
  const [result] = await db
    .select({
      name: handles.name,
      identityId: handles.identityId,
      isPrimary: handles.isPrimary,
      status: handles.status,
      publicKey: identities.publicKey,
      homeServer: identities.homeServer,
      identityStatus: identities.status,
      claimedAt: handles.claimedAt,
    })
    .from(handles)
    .innerJoin(identities, eq(handles.identityId, identities.id))
    .where(eq(handles.name, normalizedHandle))
    .limit(1);

  if (!result) {
    return c.json({ code: 'HANDLE_NOT_FOUND', message: 'Handle not found' }, 404);
  }

  if (result.status !== 'active') {
    return c.json({ code: 'HANDLE_DISABLED', message: 'Handle is no longer active' }, 410);
  }

  // Don't expose hidden identities via handle lookup
  if (result.identityStatus === 'hidden') {
    return c.json({ code: 'HANDLE_NOT_FOUND', message: 'Handle not found' }, 404);
  }

  return c.json({
    handle: result.name,
    publicKey: result.publicKey,
    identityId: result.identityId,
    homeServer: result.homeServer,
    claimedAt: result.claimedAt.toISOString(),
  });
});
