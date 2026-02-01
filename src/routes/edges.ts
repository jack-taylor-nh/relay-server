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
import { eq } from 'drizzle-orm';
import { ulid } from 'ulid';
import { randomBytes } from 'crypto';
import { db, edges, identities } from '../db';
import { verifyString, fromBase64, computeFingerprint, initCrypto } from '@relay/core';
import type { EdgeType, SecurityLevel } from '../db/schema';

export const edgeRoutes = new Hono();

// Email domain for aliases
const EMAIL_DOMAIN = 'rlymsg.com';

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
 * Create a new edge
 */
edgeRoutes.post('/', async (c) => {
  await initCrypto();

  const body = await c.req.json<{
    type: EdgeType;
    publicKey: string;
    nonce: string;
    signature: string;
    label?: string;
    customAddress?: string; // For custom contact link slugs
  }>();

  if (!body.type || !body.publicKey || !body.nonce || !body.signature) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
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

  // Generate address based on type
  let address: string;
  let securityLevel: SecurityLevel;

  switch (body.type) {
    case 'email':
      address = generateEmailAlias();
      securityLevel = 'gateway_secured';
      break;
    case 'contact_link':
      address = body.customAddress || generateContactLinkSlug();
      securityLevel = 'gateway_secured'; // Upgradeable if visitor uses Relay
      break;
    case 'native':
      // Native edges use identity ID as address
      address = identityId;
      securityLevel = 'e2ee';
      break;
    default:
      // Future bridges
      address = `${body.type}:${ulid()}`;
      securityLevel = 'gateway_secured';
  }

  // Check for address collision
  const existing = await db
    .select()
    .from(edges)
    .where(eq(edges.address, address))
    .limit(1);

  if (existing.length > 0) {
    // Retry with new address for email/contact_link
    if (body.type === 'email' || body.type === 'contact_link') {
      address = body.type === 'email' ? generateEmailAlias() : generateContactLinkSlug();
    } else {
      return c.json({ code: 'ADDRESS_TAKEN', message: 'Address already in use' }, 409);
    }
  }

  const edgeId = ulid();
  const now = new Date();

  await db.insert(edges).values({
    id: edgeId,
    identityId,
    type: body.type,
    address,
    label: body.label,
    status: 'active',
    securityLevel,
    createdAt: now,
  });

  return c.json({
    id: edgeId,
    type: body.type,
    address,
    label: body.label,
    status: 'active',
    securityLevel,
    createdAt: now.toISOString(),
  }, 201);
});

/**
 * List edges for identity
 */
edgeRoutes.get('/', async (c) => {
  await initCrypto();

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

  const userEdges = await db
    .select()
    .from(edges)
    .where(eq(edges.identityId, identityId));

  return c.json({
    edges: userEdges.map(edge => ({
      id: edge.id,
      type: edge.type,
      address: edge.address,
      label: edge.label,
      status: edge.status,
      securityLevel: edge.securityLevel,
      messageCount: edge.messageCount,
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
      publicKey: identities.publicKey,
    })
    .from(edges)
    .innerJoin(identities, eq(edges.identityId, identities.id))
    .where(eq(edges.address, address))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.status !== 'active') {
    return c.json({ code: 'EDGE_DISABLED', message: 'Edge is disabled' }, 410);
  }

  return c.json({
    id: edge.id,
    identityId: edge.identityId,
    type: edge.type,
    securityLevel: edge.securityLevel,
    publicKey: edge.publicKey,
  });
});

/**
 * Disable an edge
 */
edgeRoutes.delete('/:id', async (c) => {
  await initCrypto();

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
 * Update edge (label, policy)
 */
edgeRoutes.patch('/:id', async (c) => {
  await initCrypto();

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
