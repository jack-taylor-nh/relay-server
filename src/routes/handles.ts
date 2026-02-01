/**
 * Handle Routes
 * 
 * POST /v1/handles - Create a new handle
 * GET /v1/handles - List all handles for authenticated user
 * GET /v1/handles/:handle - Resolve handle to public key (public)
 */

import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { handles, identities } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { randomUUID } from 'crypto';

export const handleRoutes = new Hono();

// POST /v1/handles - Create a new handle
handleRoutes.post('/', authMiddleware, async (c) => {
  const identityId = c.get('identityId') as string;
  const body = await c.req.json();

  const { handle, displayName } = body;

  // Validate handle format
  if (!handle || typeof handle !== 'string') {
    return c.json({ error: 'Handle is required' }, 400);
  }

  // Handle validation: alphanumeric, underscores, hyphens, 3-32 chars, lowercase
  const handleRegex = /^[a-z0-9_-]{3,32}$/;
  if (!handleRegex.test(handle)) {
    return c.json({
      error: 'Invalid handle format. Must be 3-32 characters, lowercase letters, numbers, underscores, and hyphens only.'
    }, 400);
  }

  try {
    // Create the handle
    const [newHandle] = await db.insert(handles).values({
      id: randomUUID(),
      identityId,
      handle,
      displayName: displayName || null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }).returning();

    return c.json({
      id: newHandle.id,
      handle: newHandle.handle,
      displayName: newHandle.displayName,
      createdAt: newHandle.createdAt,
      updatedAt: newHandle.updatedAt,
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
      })
      .from(handles)
      .where(eq(handles.identityId, identityId));

    return c.json({ handles: userHandles });
  } catch (error) {
    console.error('Error fetching handles:', error);
    return c.json({ error: 'Failed to fetch handles' }, 500);
  }
});

// GET /v1/handles/:handle - Resolve handle to public key (public endpoint)
handleRoutes.get('/:handle', async (c) => {
  const handle = c.req.param('handle');

  if (!handle) {
    return c.json({ error: 'Handle is required' }, 400);
  }

  try {
    // Join handles with identities to get public key
    const result = await db
      .select({
        handle: handles.handle,
        displayName: handles.displayName,
        publicKey: identities.publicKey,
        createdAt: handles.createdAt,
      })
      .from(handles)
      .innerJoin(identities, eq(handles.identityId, identities.id))
      .where(eq(handles.handle, handle))
      .limit(1);

    if (result.length === 0) {
      return c.json({ error: 'Handle not found' }, 404);
    }

    const resolved = result[0];

    return c.json({
      handle: resolved.handle,
      displayName: resolved.displayName,
      publicKey: resolved.publicKey,
      createdAt: resolved.createdAt,
    });
  } catch (error) {
    console.error('Error resolving handle:', error);
    return c.json({ error: 'Failed to resolve handle' }, 500);
  }
});
