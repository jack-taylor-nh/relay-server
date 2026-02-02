/**
 * Edge Routes
 * 
 * Unified management of all contact surfaces (edges)
 * 
 * POST /v1/edge - Create a new edge
 * GET /v1/edges - List edges for identity
 * GET /v1/edge/:id - Get edge details
 * PATCH /v1/edge/:id - Update edge (status, label, policy)
 * DELETE /v1/edge/:id - Disable an edge
 * GET /v1/edge/lookup/:address - Lookup edge by address (for email worker)
 */

import { Hono } from 'hono';
import { eq, sql } from 'drizzle-orm';
import { ulid } from 'ulid';
import { randomBytes } from 'crypto';
import { db, edges, identities } from '../db/index.js';
import { verifyString, fromBase64, computeFingerprint } from '../core/crypto/index.js';
import { getAvailableEdgeTypes, getEdgeType, validateEdgeAddress } from '../core/edge-types.js';
import { computeQueryKey } from '../lib/queryKey.js';
import type { EdgeType, SecurityLevel } from '../db/schema.js';

export const edgeRoutes = new Hono();

// Email domain for aliases
const EMAIL_DOMAIN = 'rlymsg.com';

/**
 * GET /v1/edge/types - Get available edge types (dynamic client configuration)
 */
edgeRoutes.get('/types', async (c) => {
  const types = getAvailableEdgeTypes();
  return c.json({ types });
});

/**
 * Generate a random email alias
 */
function generateEmailAlias(): string {
  const bytes = randomBytes(4);
  const alias = bytes.toString('base64')
    .replace(/[+/=]/g, '')
    .toLowerCase()
    .slice(0, 6);
  return `${alias}@${EMAIL_DOMAIN}`;
}

/**
 * Generate a random contact link slug
 */
function generateContactLinkSlug(): string {
  const bytes = randomBytes(6);
  return bytes.toString('base64')
    .replace(/[+/=]/g, '')
    .slice(0, 8);
}

/**
 * Create a new edge (unified for all types including handles)
 */
edgeRoutes.post('/', async (c) => {
  const body = await c.req.json<{
    type: EdgeType;
    publicKey: string;
    x25519PublicKey: string;
    nonce: string;
    signature: string;
    label?: string;
    customAddress?: string; // For handles/contact links
    displayName?: string;   // For handles
  }>();

  if (!body.type || !body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Check if edge type exists and is enabled
  const edgeType = getEdgeType(body.type);
  if (!edgeType || !edgeType.enabled) {
    return c.json({ code: 'INVALID_EDGE_TYPE', message: `Edge type '${body.type}' not available` }, 400);
  }

  // Validate custom address if required
  if (edgeType.requiresCustomAddress) {
    if (!body.customAddress) {
      return c.json({ code: 'VALIDATION_ERROR', message: `Custom address required for ${edgeType.name}` }, 400);
    }
    if (!validateEdgeAddress(body.type, body.customAddress)) {
      return c.json({ code: 'VALIDATION_ERROR', message: `Invalid address format for ${edgeType.name}` }, 400);
    }
  }

  // Verify signature
  const publicKey = fromBase64(body.publicKey);
  const messageToSign = `relay-create-edge:${body.type}:${body.nonce}`;
  const isValid = verifyString(messageToSign, body.signature, publicKey);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(publicKey);

  // Ensure identity exists
  const [identity] = await db
    .select()
    .from(identities)
    .where(eq(identities.id, identityId))
    .limit(1);

  if (!identity) {
    return c.json({ code: 'IDENTITY_NOT_FOUND', message: 'Identity not registered' }, 404);
  }

  // Generate address and metadata based on type
  let address: string;
  let metadata: any = {};

  switch (body.type) {
    case 'native': {
      // Handle (native edge)
      if (!body.customAddress) {
        return c.json({ code: 'VALIDATION_ERROR', message: 'Handle name required' }, 400);
      }

      const handleName = body.customAddress.toLowerCase();
      
      // Check if handle already exists
      const existingHandle = await db
        .select()
        .from(edges)
        .where(eq(edges.address, handleName))
        .limit(1);

      if (existingHandle.length > 0) {
        return c.json({ code: 'HANDLE_TAKEN', message: 'Handle already taken' }, 409);
      }

      address = handleName;
      metadata = {
        handle: handleName,
        displayName: body.displayName || null,
      };

      break;
    }

    case 'email':
      address = generateEmailAlias();
      break;

    case 'contact_link':
      address = body.customAddress || generateContactLinkSlug();
      break;

    default:
      // Future bridges
      address = body.customAddress || `${body.type}:${ulid()}`;
  }

  const edgeId = ulid();
  const now = new Date();

  // Compute zero-knowledge query key for edge ownership
  const ownerQueryKey = computeQueryKey(identityId);

  await db.insert(edges).values({
    id: edgeId,
    identityId,
    ownerQueryKey,
    type: body.type,
    bridgeType: body.type,
    isNative: body.type === 'native',
    address,
    label: body.label,
    status: 'active',
    securityLevel: edgeType.securityLevel,
    x25519PublicKey: body.x25519PublicKey || null,
    metadata,
    createdAt: now,
  });

  return c.json({
    id: edgeId,
    type: body.type,
    address: body.type === 'native' ? address : address,
    label: body.label,
    status: 'active',
    securityLevel: edgeType.securityLevel,
    metadata,
    createdAt: now.toISOString(),
  }, 201);
});

/**
 * List edges for identity
 */
edgeRoutes.get('/', async (c) => {
  const publicKey = c.req.header('X-Relay-PublicKey');
  const signature = c.req.header('X-Relay-Signature');
  const nonce = c.req.header('X-Relay-Nonce');

  if (!publicKey || !signature || !nonce) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing auth headers' }, 401);
  }

  const pubkeyBytes = fromBase64(publicKey);
  const messageToSign = `relay-list-edges:${nonce}`;
  const isValid = verifyString(messageToSign, signature, pubkeyBytes);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(pubkeyBytes);

  // Use zero-knowledge query key for filtering (server cannot link queryKey → identityId)
  const ownerQueryKey = computeQueryKey(identityId);

  const userEdges = await db
    .select()
    .from(edges)
    .where(eq(edges.ownerQueryKey, ownerQueryKey));

  return c.json({
    edges: userEdges.map(edge => ({
      id: edge.id,
      type: edge.type,
      address: edge.isNative ? edge.address : edge.address,
      label: edge.label,
      status: edge.status,
      securityLevel: edge.securityLevel,
      messageCount: edge.messageCount,
      metadata: edge.metadata, // Includes handle/displayName for native edges
      createdAt: edge.createdAt.toISOString(),
      lastActivityAt: edge.lastActivityAt?.toISOString() || null,
    })),
  });
});

/**
 * Lookup edge by address (for email worker, public endpoint)
 */
edgeRoutes.get('/lookup/:address', async (c) => {
  const address = c.req.param('address');

  const [edge] = await db
    .select({
      id: edges.id,
      identityId: edges.identityId,
      type: edges.type,
      status: edges.status,
      securityLevel: edges.securityLevel,
      x25519PublicKey: edges.x25519PublicKey,
    })
    .from(edges)
    .where(eq(edges.address, address))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.status !== 'active') {
    return c.json({ code: 'EDGE_DISABLED', message: 'Edge is disabled' }, 410);
  }

  if (!edge.x25519PublicKey) {
    return c.json({ code: 'MISSING_ENCRYPTION_KEY', message: 'Edge missing encryption key - please recreate' }, 500);
  }

  return c.json({
    id: edge.id,
    identityId: edge.identityId,
    type: edge.type,
    securityLevel: edge.securityLevel,
    publicKey: edge.x25519PublicKey,  // Use stored X25519 key
  });
});

/**
 * Disable an edge
 */
edgeRoutes.delete('/:id', async (c) => {
  const edgeId = c.req.param('id');

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
  const messageToSign = `relay-disable-edge:${edgeId}:${body.nonce}`;
  const isValid = verifyString(messageToSign, body.signature, publicKey);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(publicKey);

  // Find edge and verify ownership
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.identityId !== identityId) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this edge' }, 403);
  }

  // Disable the edge
  await db
    .update(edges)
    .set({ status: 'disabled', disabledAt: new Date() })
    .where(eq(edges.id, edgeId));

  return c.json({ message: 'Edge disabled', id: edgeId });
});

/**
 * Burn (permanently dispose) an edge
 * 
 * Burns the edge by:
 * - Setting status to 'burned'
 * - NULLing identityId and handleId (makes edge untraceable)
 * - Keeping address record (prevents reuse/collision)
 * - Conversations remain but can't be traced back to identity
 */
edgeRoutes.post('/:id/burn', async (c) => {
  const edgeId = c.req.param('id');

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
  const messageToSign = `relay-burn-edge:${edgeId}:${body.nonce}`;
  
  const isValid = verifyString(messageToSign, body.signature, publicKey);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(publicKey);

  // Find edge and verify ownership
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.identityId !== identityId) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this edge' }, 403);
  }

  if (edge.status === 'burned') {
    return c.json({ code: 'ALREADY_BURNED', message: 'Edge is already burned' }, 400);
  }

  // Burn the edge: NULL all linkable data to make permanently untraceable
  // Address stays to prevent collision but becomes anonymous
  await db
    .update(edges)
    .set({
      ownerQueryKey: sql`NULL`,  // Critical: breaks zero-knowledge query linkage
      identityId: sql`NULL`,     // Unlink from identity (untraceable)
      metadata: {},              // Clear encrypted data (handle, displayName, etc.)
      status: 'burned',
      disabledAt: new Date(),
    })
    .where(eq(edges.id, edgeId));

  return c.json({
    message: 'Edge burned and unlinked from identity',
    id: edgeId,
    note: 'This edge address is permanently reserved and cannot be reused',
  });
});

/**
 * Update edge (label, policy)
 */
edgeRoutes.patch('/:id', async (c) => {
  const edgeId = c.req.param('id');

  const body = await c.req.json<{
    publicKey: string;
    nonce: string;
    signature: string;
    label?: string;
    policy?: object;
  }>();

  if (!body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Verify ownership
  const publicKey = fromBase64(body.publicKey);
  const messageToSign = `relay-update-edge:${edgeId}:${body.nonce}`;
  const isValid = verifyString(messageToSign, body.signature, publicKey);

  if (!isValid) {
    return c.json({ code: 'INVALID_SIGNATURE', message: 'Signature verification failed' }, 401);
  }

  const identityId = computeFingerprint(publicKey);

  // Find edge and verify ownership
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.identityId !== identityId) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this edge' }, 403);
  }

  // Build update object
  const updates: Partial<typeof edge> = {};
  if (body.label !== undefined) updates.label = body.label;
  if (body.policy !== undefined) updates.policy = body.policy as any;

  await db
    .update(edges)
    .set(updates)
    .where(eq(edges.id, edgeId));

  return c.json({ message: 'Edge updated', id: edgeId, ...updates });
});
