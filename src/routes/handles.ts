/**
 * Handle Routes
 * 
 * POST /v1/handles - Create a new handle
 * GET /v1/handles - List all handles for authenticated user
 * GET /v1/handles/:handle - Resolve handle to public key (DEPRECATED)
 * POST /v1/handles/resolve - Resolve handle (DEPRECATED)
 * 
 * NOTE: For new code, use POST /v1/edge/resolve instead
 */

import { Hono } from 'hono';
import { eq, and, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { handles, edges } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { randomUUID } from 'crypto';

export const handleRoutes = new Hono();

// POST /v1/handles - Create a new handle
handleRoutes.post('/', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;
  const body = await c.req.json();

  const { handle, displayName, x25519PublicKey } = body;

  // Validate handle format
  if (!handle || typeof handle !== 'string') {
    return c.json({ error: 'Handle is required' }, 400);
  }

  // Validate x25519PublicKey
  if (!x25519PublicKey || typeof x25519PublicKey !== 'string') {
    return c.json({ error: 'x25519PublicKey is required for edge encryption' }, 400);
  }

  // Handle validation: alphanumeric, underscores, hyphens, 3-32 chars, lowercase
  const handleRegex = /^[a-z0-9_-]{3,32}$/;
  if (!handleRegex.test(handle)) {
    return c.json({
      error: 'Invalid handle format. Must be 3-32 characters, lowercase letters, numbers, underscores, and hyphens only.'
    }, 400);
  }

  try {
    const now = new Date();

    // Create the handle
    const [newHandle] = await db.insert(handles).values({
      id: randomUUID(),
      identityId,
      handle,
      displayName: displayName || null,
      createdAt: now,
      updatedAt: now,
    }).returning();

    // Auto-create native edge for this handle
    const { ulid } = await import('ulid');
    const { computeQueryKey } = await import('../lib/queryKey.js');
    const ownerQueryKey = computeQueryKey(identityId);
    
    const [nativeEdge] = await db.insert(edges).values({
      id: ulid(),
      identityId,
      ownerQueryKey,
      // handleId: newHandle.id,  // Deprecated - removed in zero-knowledge refactor
      type: 'native',
      bridgeType: 'native',
      isNative: true,
      address: handle,  // Native edge address is the handle
      status: 'active',
      securityLevel: 'e2ee',
      x25519PublicKey,  // Store edge-level encryption key
      metadata: {},
      createdAt: now,
      messageCount: 0,
    }).returning();

    return c.json({
      id: newHandle.id,
      handle: newHandle.handle,
      displayName: newHandle.displayName,
      createdAt: newHandle.createdAt,
      updatedAt: newHandle.updatedAt,
      nativeEdge: {
        id: nativeEdge.id,
        address: nativeEdge.address,
        type: nativeEdge.type,
      },
    }, 201);
  } catch (error: any) {
    // Handle unique constraint violation
    if (error.code === '23505') {
      return c.json({ error: 'Handle already taken' }, 409);
    }
    console.error('Error creating handle:', error);
    return c.json({ error: 'Failed to create handle' }, 500);
  }
});

// GET /v1/handles - List all handles for authenticated user
handleRoutes.get('/', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;

  try {
    const userHandles = await db
      .select({
        id: handles.id,
        handle: handles.handle,
        displayName: handles.displayName,
        createdAt: handles.createdAt,
        updatedAt: handles.updatedAt,
        nativeEdgeId: edges.id,
      })
      .from(handles)
      .leftJoin(edges, and(
        // eq(edges.handleId, handles.id),  // Deprecated - removed in zero-knowledge refactor
        eq(edges.address, handles.handle),  // Match by address instead
        eq(edges.isNative, true)
      ))
      .where(eq(handles.identityId, identityId));

    return c.json({ handles: userHandles });
  } catch (error) {
    console.error('Error fetching handles:', error);
    return c.json({ error: 'Failed to fetch handles' }, 500);
  }
});

// POST /v1/handles/resolve - Resolve handle to public key
// @deprecated Use POST /v1/edge/resolve with { type: 'native', address: handle } instead
// SECURITY: This endpoint has been updated to NOT return identity public key
handleRoutes.post('/resolve', async (c) => {
  // Add deprecation header
  c.header('X-Deprecated', 'Use POST /v1/edge/resolve instead');
  
  try {
    const body = await c.req.json<{ handle: string }>();
    const handle = body.handle?.trim().toLowerCase();

    if (!handle) {
      return c.json({ error: 'Handle is required' }, 400);
    }

    // Query edges table for native edge (handle) - NO identity join
    const result = await db
      .select({
        handle: edges.address,
        displayName: sql<string>`${edges.metadata}->>'displayName'`,
        x25519PublicKey: edges.x25519PublicKey,  // Edge-level encryption key
        edgeId: edges.id,
        createdAt: edges.createdAt,
      })
      .from(edges)
      .where(and(
        eq(edges.address, handle),
        eq(edges.type, 'native'),
        eq(edges.status, 'active')
      ))
      .limit(1);

    if (result.length === 0) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    const resolved = result[0];

    // Return ONLY edge data - NO identity public key
    return c.json({
      handle: resolved.handle,
      displayName: resolved.displayName,
      x25519PublicKey: resolved.x25519PublicKey,
      edgeId: resolved.edgeId,
      createdAt: resolved.createdAt,
      // NOTE: publicKey (identity key) intentionally NOT returned for privacy
    });
  } catch (error) {
    console.error('Error resolving handle:', {
      code: (error as any).code,
      message: 'Failed to resolve handle',
    });
    return c.json({ error: 'Failed to resolve handle' }, 500);
  }
});

// GET /v1/handles/:handle - Resolve handle to public key
// @deprecated Use POST /v1/edge/resolve instead
// ⚠️ SECURITY: Handle appears in URL path and server logs
// SECURITY: Updated to NOT return identity public key
handleRoutes.get('/:handle', async (c) => {
  // Add deprecation header
  c.header('X-Deprecated', 'Use POST /v1/edge/resolve instead');
  
  const handle = c.req.param('handle');

  if (!handle) {
    return c.json({ error: 'Handle is required' }, 400);
  }

  try {
    // Query edges table for native edge (handle) - NO identity join
    const result = await db
      .select({
        handle: edges.address,
        displayName: sql<string>`${edges.metadata}->>'displayName'`,
        x25519PublicKey: edges.x25519PublicKey,  // Edge-level encryption key
        edgeId: edges.id,
        createdAt: edges.createdAt,
      })
      .from(edges)
      .where(and(
        eq(edges.address, handle),
        eq(edges.type, 'native'),
        eq(edges.status, 'active')
      ))
      .limit(1);

    if (result.length === 0) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    const resolved = result[0];

    // Return ONLY edge data - NO identity public key
    return c.json({
      handle: resolved.handle,
      displayName: resolved.displayName,
      x25519PublicKey: resolved.x25519PublicKey,
      edgeId: resolved.edgeId,
      createdAt: resolved.createdAt,
      // NOTE: publicKey (identity key) intentionally NOT returned for privacy
    });
  } catch (error) {
    console.error('Error resolving handle:', {
      code: (error as any).code,
      message: 'Failed to resolve handle',
    });
    return c.json({ error: 'Failed to resolve handle' }, 500);
  }
});

// DELETE /v1/handles/:id - Delete a handle
handleRoutes.delete('/:id', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;
  const handleId = c.req.param('id');

  if (!handleId) {
    return c.json({ error: 'Handle ID is required' }, 400);
  }

  try {
    // Verify ownership and delete
    const result = await db
      .delete(handles)
      .where(eq(handles.id, handleId))
      .returning({ id: handles.id, identityId: handles.identityId });

    if (result.length === 0) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    // Verify the handle belonged to the authenticated user
    if (result[0].identityId !== identityId) {
      return c.json({ error: 'Unauthorized' }, 403);
    }

    return c.json({ message: 'Handle deleted', id: handleId });
  } catch (error) {
    console.error('Error deleting handle:', error);
    return c.json({ error: 'Failed to delete handle' }, 500);
  }
});
