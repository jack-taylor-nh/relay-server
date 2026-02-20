/**
 * Edge Routes
 * 
 * Unified management of all contact surfaces (edges)
 * 
 * POST /v1/edge - Create a new edge
 * POST /v1/edge/resolve - Unified edge resolution (preferred)
 * GET /v1/edges - List edges for identity
 * GET /v1/edge/:id - Get edge details
 * PATCH /v1/edge/:id - Update edge (status, label, policy)
 * DELETE /v1/edge/:id - Disable an edge
 * GET /v1/edge/lookup/:address - Lookup edge by address (DEPRECATED: use resolve)
 */

import { Hono } from 'hono';
import { eq, and, sql } from 'drizzle-orm';
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
 * POST /v1/edge/resolve - Unified edge resolution
 * 
 * Resolves any edge type to its encryption key.
 * Returns ONLY edge data - NO identity information.
 * 
 * Supports:
 * - native: Handle lookup (address = handle name)
 * - email: Email alias lookup (address = alias@rlymsg.com)
 * - contact_link: Contact link lookup (address = slug)
 * - bridge: Bridge edge lookup (address = bridge name, e.g., "email")
 */
edgeRoutes.post('/resolve', async (c) => {
  console.log('[/edge/resolve] Request received');
  try {
    const body = await c.req.json<{ 
      type: EdgeType | 'bridge';
      address: string;
    }>();
    
    console.log('[/edge/resolve] Body:', JSON.stringify(body));

    const type = body.type;
    const address = body.address?.trim().toLowerCase();

    if (!type || !address) {
      console.log('[/edge/resolve] Missing type or address');
      return c.json({ 
        code: 'VALIDATION_ERROR', 
        message: 'Both type and address are required' 
      }, 400);
    }
    
    console.log('[/edge/resolve] Looking up edge:', { type, address });

    // Handle bridge edge resolution (special case)
    if (type === 'bridge') {
      // Bridge edges are well-known edges with static X25519 keys
      // The bridge public key is stored in the database as a special edge
      
      // Look up bridge edge by address (e.g., "email")
      const bridgeResult = await db
        .select({
          edgeId: edges.id,
          address: edges.address,
          type: edges.type,
          status: edges.status,
          securityLevel: edges.securityLevel,
          x25519PublicKey: edges.x25519PublicKey,
        })
        .from(edges)
        .where(and(
          eq(edges.address, address),
          eq(edges.type, 'bridge' as EdgeType),
          eq(edges.status, 'active')
        ))
        .limit(1);

      if (bridgeResult.length > 0 && bridgeResult[0].x25519PublicKey) {
        return c.json({
          edgeId: bridgeResult[0].edgeId,
          type: 'bridge',
          status: bridgeResult[0].status,
          securityLevel: bridgeResult[0].securityLevel,
          x25519PublicKey: bridgeResult[0].x25519PublicKey,
          displayName: `${address.charAt(0).toUpperCase() + address.slice(1)} Bridge`,
        });
      }

      // Fallback: For "email" bridge, provide the worker endpoint
      // This allows gradual migration - clients can fetch from worker directly
      if (address === 'email') {
        return c.json({
          code: 'BRIDGE_REDIRECT',
          message: 'Bridge public key not yet stored in database. Use worker endpoint.',
          workerUrl: 'https://relay-email-worker.taylor-d-jack.workers.dev/public-key',
        }, 307);
      }
      
      return c.json({ 
        code: 'UNKNOWN_BRIDGE', 
        message: `Unknown bridge: ${address}` 
      }, 404);
    }

    // For webhook edges, extract edge ID from the full URL format
    // Input format: "webhook.rlymsg.com/w/{edgeId}" -> extract just the edgeId
    // The database stores just the edgeId as the address
    let lookupAddress = address;
    if (type === 'webhook') {
      const webhookMatch = address.match(/^(?:https?:\/\/)?webhook\.rlymsg\.com\/w\/([a-z0-9]+)$/i);
      if (webhookMatch) {
        lookupAddress = webhookMatch[1].toUpperCase(); // ULIDs are uppercase
        console.log('[/edge/resolve] Extracted webhook edge ID:', lookupAddress);
      }
    }

    // Query edge by type and address
    const result = await db
      .select({
        edgeId: edges.id,
        address: edges.address,
        type: edges.type,
        status: edges.status,
        securityLevel: edges.securityLevel,
        x25519PublicKey: edges.x25519PublicKey,
        displayName: sql<string>`${edges.metadata}->>'displayName'`,
        authToken: sql<string>`${edges.metadata}->>'authToken'`, // For webhook edges
      })
      .from(edges)
      .where(and(
        eq(edges.address, lookupAddress),
        eq(edges.type, type),
        eq(edges.status, 'active')
      ))
      .limit(1);

    if (result.length === 0) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: `${type} edge not found: ${lookupAddress}` 
      }, 404);
    }

    const edge = result[0];

    if (!edge.x25519PublicKey) {
      return c.json({ 
        code: 'MISSING_ENCRYPTION_KEY', 
        message: 'Edge missing encryption key' 
      }, 500);
    }

    // Return ONLY edge data - NO identity information
    return c.json({
      edgeId: edge.edgeId,
      type: edge.type,
      status: edge.status,
      securityLevel: edge.securityLevel,
      x25519PublicKey: edge.x25519PublicKey,
      displayName: edge.displayName || null,
      authToken: edge.authToken || null, // For webhook edges
    });

  } catch (error) {
    console.error('Error resolving edge:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to resolve edge' 
    }, 500);
  }
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
    // Encrypted fields (client-side encrypted, server stores opaque blob)
    encryptedLabel?: string;
    encryptedMetadata?: string;
    customAddress?: string; // For handles/contact links
    authToken?: string; // For webhook edges
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

  // Generate edge ID first (needed for webhook address)
  const edgeId = ulid();

  // Generate address and metadata based on type
  let address: string;
  let metadata: any = {};

  switch (body.type) {
    case 'native':
    case 'discord': {
      // Handle-based edges (native and discord share format, separate namespaces)
      if (!body.customAddress) {
        return c.json({ code: 'VALIDATION_ERROR', message: 'Handle name required' }, 400);
      }

      const handleName = body.customAddress.toLowerCase();
      
      // Check if handle already exists FOR THIS TYPE
      // (same handle can exist across different types)
      const existingHandle = await db
        .select()
        .from(edges)
        .where(and(
          eq(edges.type, body.type),
          eq(edges.address, handleName)
        ))
        .limit(1);

      if (existingHandle.length > 0) {
        return c.json({ code: 'HANDLE_TAKEN', message: 'Handle already taken' }, 409);
      }

      address = handleName;
      // Store ONLY encrypted metadata - no plaintext handle (address field has it)
      metadata = body.encryptedMetadata ? { encrypted: body.encryptedMetadata } : {};

      break;
    }

    case 'email':
      address = generateEmailAlias();
      break;

    case 'contact_link':
      address = body.customAddress || generateContactLinkSlug();
      break;

    case 'webhook':
      // Webhook edges use their ID as address (for URL routing)
      // authToken stored in metadata for verification
      address = edgeId; // Will be set after ulid() generation
      if (body.authToken) {
        metadata = { authToken: body.authToken };
      } else {
        return c.json({ code: 'VALIDATION_ERROR', message: 'authToken required for webhook edges' }, 400);
      }
      break;

    case 'local-llm':
      // Local LLM edges store the bridge's edge ID as the address
      // This is the edge ID of the desktop bridge app (passed as customAddress)
      // The client uses this to resolve the bridge's X25519 public key
      console.log('[POST /edge] local-llm edge creation:', {
        hasCustomAddress: !!body.customAddress,
        customAddress: body.customAddress?.substring(0, 10),
      });
      if (!body.customAddress) {
        console.log('[POST /edge] ❌ Missing customAddress for local-llm edge');
        return c.json({ code: 'VALIDATION_ERROR', message: 'Bridge edge ID required for local-llm edges' }, 400);
      }
      address = body.customAddress; // Store the bridge's edge ID
      console.log('[POST /edge] ✅ local-llm edge address set to:', address.substring(0, 10));
      metadata = body.encryptedMetadata ? { encrypted: body.encryptedMetadata } : {};
      break;

    default:
      // Future bridges
      address = body.customAddress || `${body.type}:${ulid()}`;
  }

  const now = new Date();

  // Compute zero-knowledge query key for edge ownership
  const ownerQueryKey = computeQueryKey(identityId);

  // SECURITY: Do NOT store identityId - use ownerQueryKey for ownership verification
  // This preserves edge unlinkability - can't trace edge → identity from DB alone
  await db.insert(edges).values({
    id: edgeId,
    // identityId intentionally NOT stored - breaks unlinkability
    ownerQueryKey,
    type: body.type,
    bridgeType: body.type,
    isNative: body.type === 'native',
    address,
    // Store encrypted label (opaque to server)
    label: body.encryptedLabel || null,
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
    // Return encrypted values for client to decrypt
    encryptedLabel: body.encryptedLabel || null,
    encryptedMetadata: body.encryptedMetadata || null,
    status: 'active',
    securityLevel: edgeType.securityLevel,
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
    edges: userEdges.map(edge => {
      const edgeData: any = {
        id: edge.id,
        type: edge.type,
        address: edge.isNative ? edge.address : edge.address,
        // Return encrypted label for client to decrypt
        encryptedLabel: edge.label,
        // Return encrypted metadata for client to decrypt
        encryptedMetadata: (edge.metadata as any)?.encrypted || null,
        status: edge.status,
        securityLevel: edge.securityLevel,
        messageCount: edge.messageCount,
        hasX25519: !!edge.x25519PublicKey, // Client can check if migration needed
        createdAt: edge.createdAt.toISOString(),
        lastActivityAt: edge.lastActivityAt?.toISOString() || null,
      };

      // For webhook edges, include webhookUrl and authToken in metadata
      if (edge.type === 'webhook' && edge.metadata) {
        const webhookWorkerUrl = process.env.WEBHOOK_WORKER_URL || 'https://webhook.rlymsg.com';
        edgeData.metadata = {
          webhookUrl: `${webhookWorkerUrl}/w/${edge.id}`,
          authToken: (edge.metadata as any).authToken || null,
        };
      }

      return edgeData;
    }),
  });
});

/**
 * GET /v1/edge/:id - Get edge details by ID (public endpoint)
 * 
 * Returns public edge information including X25519 public key.
 * No authentication required - this is for resolving edges for messaging.
 * Similar to /v1/edge/resolve but looks up by edge ID instead of type+address.
 */
edgeRoutes.get('/:id', async (c) => {
  const edgeId = c.req.param('id');

  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ 
      code: 'EDGE_NOT_FOUND', 
      message: 'Edge not found' 
    }, 404);
  }

  if (edge.status !== 'active') {
    return c.json({ 
      code: 'EDGE_DISABLED', 
      message: 'Edge is no longer active' 
    }, 410);
  }

  if (!edge.x25519PublicKey) {
    return c.json({ 
      code: 'MISSING_ENCRYPTION_KEY', 
      message: 'Edge missing encryption key' 
    }, 500);
  }

  // Return ONLY public edge data - NO identity information
  return c.json({
    edgeId: edge.id,
    type: edge.type,
    address: edge.address,
    status: edge.status,
    securityLevel: edge.securityLevel,
    x25519PublicKey: edge.x25519PublicKey,
    displayName: (edge.metadata as any)?.displayName || null,
    createdAt: edge.createdAt.toISOString(),
  });
});

/**
 * Lookup edge by address (for email worker, public endpoint)
 * @deprecated Use POST /v1/edge/resolve instead
 */
edgeRoutes.get('/lookup/:address', async (c) => {
  // Add deprecation header
  c.header('X-Deprecated', 'Use POST /v1/edge/resolve instead');
  
  const address = c.req.param('address');

  const [edge] = await db
    .select({
      id: edges.id,
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
    // NOTE: identityId intentionally NOT returned - prevents edge → identity linkage
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

  // Find edge and verify ownership via ownerQueryKey (not identity_id)
  const expectedQueryKey = computeQueryKey(identityId);
  
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  // SECURITY: Verify ownership via ownerQueryKey, not identity_id
  if (edge.ownerQueryKey !== expectedQueryKey) {
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

  // Find edge and verify ownership via ownerQueryKey (not identity_id)
  const expectedQueryKey = computeQueryKey(identityId);
  
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  // SECURITY: Verify ownership via ownerQueryKey, not identity_id
  if (edge.ownerQueryKey !== expectedQueryKey) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this edge' }, 403);
  }

  if (edge.status === 'burned') {
    return c.json({ code: 'ALREADY_BURNED', message: 'Edge is already burned' }, 400);
  }

  // Burn the edge: NULL ownerQueryKey to make permanently untraceable
  // Address stays to prevent collision but becomes anonymous
  await db
    .update(edges)
    .set({
      ownerQueryKey: sql`NULL`,  // Critical: breaks zero-knowledge query linkage
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
 * Update edge (label, policy, x25519PublicKey)
 */
edgeRoutes.patch('/:id', async (c) => {
  const edgeId = c.req.param('id');

  const body = await c.req.json<{
    publicKey: string;
    nonce: string;
    signature: string;
    label?: string;
    policy?: object;
    x25519PublicKey?: string;  // Can be set once if missing
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

  // Find edge and verify ownership via ownerQueryKey (not identity_id)
  const expectedQueryKey = computeQueryKey(identityId);
  
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  // SECURITY: Verify ownership via ownerQueryKey, not identity_id
  if (edge.ownerQueryKey !== expectedQueryKey) {
    return c.json({ code: 'FORBIDDEN', message: 'You do not own this edge' }, 403);
  }

  // Build update object
  const updates: Partial<typeof edge> = {};
  if (body.label !== undefined) updates.label = body.label;
  if (body.policy !== undefined) updates.policy = body.policy as any;
  
  // Allow setting X25519 key if not already set (one-time migration for old edges)
  if (body.x25519PublicKey !== undefined) {
    if (edge.x25519PublicKey && edge.x25519PublicKey !== body.x25519PublicKey) {
      // Don't allow changing existing key (security measure)
      console.log(`[Edge Update] Ignoring x25519 change for edge ${edgeId} - key already set`);
    } else {
      updates.x25519PublicKey = body.x25519PublicKey;
      console.log(`[Edge Update] Setting x25519 for edge ${edgeId}`);
    }
  }

  if (Object.keys(updates).length > 0) {
    await db
      .update(edges)
      .set(updates)
      .where(eq(edges.id, edgeId));
  }

  return c.json({ message: 'Edge updated', id: edgeId, ...updates });
});
