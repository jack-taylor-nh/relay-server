/**
 * Handle Routes (Edge-Only Implementation)
 * 
 * POST /v1/handles - Create a new handle (creates native edge)
 * GET /v1/handles - List all handles for authenticated user (queries native edges)
 * DELETE /v1/handles/:id - Delete a handle (burns the native edge)
 * POST /v1/handles/resolve - Resolve handle (DEPRECATED - use /v1/edge/resolve)
 * GET /v1/handles/:handle - Resolve handle (DEPRECATED - use /v1/edge/resolve)
 * 
 * ARCHITECTURE NOTE: Handles are now just native edges with type='native'.
 * The handles table is deprecated and will be dropped.
 * This file maintains API compatibility while working purely with edges.
 */

import { Hono } from 'hono';
import { eq, and, sql } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { edges } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { computeQueryKey } from '../lib/queryKey.js';

export const handleRoutes = new Hono();

/**
 * POST /v1/handles - Create a new handle
 * 
 * Creates a native edge with the handle as the address.
 * No handles table involved - pure edge creation.
 */
handleRoutes.post('/', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;
  const body = await c.req.json();

  // Accept encrypted metadata instead of plaintext displayName
  const { handle, encryptedMetadata, x25519PublicKey } = body;

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
    const edgeId = ulid();
    
    // SECURITY: Use ownerQueryKey, NOT identityId
    const ownerQueryKey = computeQueryKey(identityId);
    
    // Create native edge - this IS the handle
    // Store encrypted metadata as opaque blob (server cannot read)
    const [nativeEdge] = await db.insert(edges).values({
      id: edgeId,
      // SECURITY: Do NOT store identityId - use ownerQueryKey for ownership
      ownerQueryKey,
      type: 'native',
      bridgeType: 'native',
      isNative: true,
      address: handle,  // Handle name is the edge address
      label: null,      // Label is now encrypted client-side
      status: 'active',
      securityLevel: 'e2ee',
      x25519PublicKey,
      // Store encrypted metadata (opaque to server)
      metadata: encryptedMetadata ? { encrypted: encryptedMetadata } : {},
      createdAt: now,
      messageCount: 0,
    }).returning();

    // Return response compatible with old handles API
    // Note: displayName is now encrypted, client will decrypt
    return c.json({
      id: nativeEdge.id,  // Edge ID serves as handle ID
      handle: nativeEdge.address,
      encryptedMetadata: encryptedMetadata || null,
      createdAt: nativeEdge.createdAt,
      updatedAt: nativeEdge.createdAt,
      nativeEdge: {
        id: nativeEdge.id,
        address: nativeEdge.address,
        type: nativeEdge.type,
      },
    }, 201);
  } catch (error: any) {
    // Handle unique constraint violation (address already exists)
    if (error.code === '23505') {
      return c.json({ error: 'Handle already taken' }, 409);
    }
    console.error('Error creating handle:', error);
    return c.json({ error: 'Failed to create handle' }, 500);
  }
});

/**
 * GET /v1/handles - List all handles for authenticated user
 * 
 * Queries native edges owned by the user via ownerQueryKey.
 * No handles table involved.
 */
handleRoutes.get('/', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;

  try {
    // SECURITY: Query by ownerQueryKey, NOT identityId
    const ownerQueryKey = computeQueryKey(identityId);
    
    const nativeEdges = await db
      .select({
        id: edges.id,
        address: edges.address,
        label: edges.label,
        status: edges.status,
        x25519PublicKey: edges.x25519PublicKey,
        createdAt: edges.createdAt,
        metadata: edges.metadata,
      })
      .from(edges)
      .where(and(
        eq(edges.ownerQueryKey, ownerQueryKey),
        eq(edges.isNative, true),
        eq(edges.status, 'active')
      ));

    // Transform to handles format for API compatibility
    const handles = nativeEdges.map(edge => ({
      id: edge.id,
      handle: edge.address,
      displayName: (edge.metadata as any)?.displayName || edge.label || null,
      createdAt: edge.createdAt,
      updatedAt: edge.createdAt,  // Edges don't track updatedAt separately
      nativeEdgeId: edge.id,
    }));

    return c.json({ handles });
  } catch (error) {
    console.error('Error fetching handles:', error);
    return c.json({ error: 'Failed to fetch handles' }, 500);
  }
});

/**
 * POST /v1/handles/resolve - Resolve handle to edge info
 * @deprecated Use POST /v1/edge/resolve with { type: 'native', address: handle } instead
 */
handleRoutes.post('/resolve', async (c) => {
  c.header('X-Deprecated', 'Use POST /v1/edge/resolve instead');
  
  try {
    const body = await c.req.json<{ handle: string }>();
    const handle = body.handle?.trim().toLowerCase();

    if (!handle) {
      return c.json({ error: 'Handle is required' }, 400);
    }

    // Query native edge by address
    const [result] = await db
      .select({
        handle: edges.address,
        displayName: sql<string>`${edges.metadata}->>'displayName'`,
        x25519PublicKey: edges.x25519PublicKey,
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

    if (!result) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    // SECURITY: Return ONLY edge data - NO identity information
    return c.json({
      handle: result.handle,
      displayName: result.displayName,
      x25519PublicKey: result.x25519PublicKey,
      edgeId: result.edgeId,
      createdAt: result.createdAt,
    });
  } catch (error) {
    console.error('Error resolving handle:', error);
    return c.json({ error: 'Failed to resolve handle' }, 500);
  }
});

/**
 * GET /v1/handles/:handle - Resolve handle to edge info
 * @deprecated Use POST /v1/edge/resolve instead (handle in URL is a privacy leak)
 */
handleRoutes.get('/:handle', async (c) => {
  c.header('X-Deprecated', 'Use POST /v1/edge/resolve instead');
  
  const handle = c.req.param('handle')?.trim().toLowerCase();

  if (!handle) {
    return c.json({ error: 'Handle is required' }, 400);
  }

  try {
    // Query native edge by address
    const [result] = await db
      .select({
        handle: edges.address,
        displayName: sql<string>`${edges.metadata}->>'displayName'`,
        x25519PublicKey: edges.x25519PublicKey,
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

    if (!result) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    // SECURITY: Return ONLY edge data - NO identity information
    return c.json({
      handle: result.handle,
      displayName: result.displayName,
      x25519PublicKey: result.x25519PublicKey,
      edgeId: result.edgeId,
      createdAt: result.createdAt,
    });
  } catch (error) {
    console.error('Error resolving handle:', error);
    return c.json({ error: 'Failed to resolve handle' }, 500);
  }
});

/**
 * DELETE /v1/handles/:id - Delete a handle (burn the edge)
 * 
 * Burns the native edge, making it untraceable.
 */
handleRoutes.delete('/:id', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;
  const edgeId = c.req.param('id');

  if (!edgeId) {
    return c.json({ error: 'Handle ID is required' }, 400);
  }

  try {
    // SECURITY: Verify ownership via ownerQueryKey
    const ownerQueryKey = computeQueryKey(identityId);
    
    const [edge] = await db
      .select({ id: edges.id, ownerQueryKey: edges.ownerQueryKey })
      .from(edges)
      .where(eq(edges.id, edgeId))
      .limit(1);

    if (!edge) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    if (edge.ownerQueryKey !== ownerQueryKey) {
      return c.json({ error: 'Unauthorized' }, 403);
    }

    // Burn the edge (NULL ownerQueryKey, set status to burned)
    await db
      .update(edges)
      .set({
        ownerQueryKey: sql`NULL`,
        metadata: {},
        status: 'burned',
        disabledAt: new Date(),
      })
      .where(eq(edges.id, edgeId));

    return c.json({ message: 'Handle deleted', id: edgeId });
  } catch (error) {
    console.error('Error deleting handle:', error);
    return c.json({ error: 'Failed to delete handle' }, 500);
  }
});
