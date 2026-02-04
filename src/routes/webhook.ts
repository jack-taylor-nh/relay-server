/**
 * Webhook Bridge Routes
 * 
 * Handles incoming webhooks from external services via webhook worker
 * 
 * POST /v1/webhook/inbound - Process inbound webhook (worker-authenticated)
 */

import { Hono } from 'hono';
import { eq, and, inArray } from 'drizzle-orm';
import { ulid } from 'ulid';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { db, edges, conversations, conversationParticipants, messages, bridgeMessages } from '../db/index.js';
import { invalidateCache, publish } from '../core/redis.js';

const { decodeBase64 } = naclUtil;

export const webhookRoutes = new Hono();

// Simple worker auth - shared secret
const WORKER_SECRET = process.env.WORKER_SECRET || 'dev-worker-secret';
const WORKER_PUBLIC_KEY = process.env.WORKER_PUBLIC_KEY; // Ed25519 public key (hex) for signature verification

/**
 * Middleware to verify worker auth
 */
async function workerAuthMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Worker ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Invalid worker auth' }, 401);
  }
  
  const secret = authHeader.slice(7);
  if (secret !== WORKER_SECRET) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Invalid worker secret' }, 401);
  }
  
  // Verify signature if provided (optional for backwards compatibility)
  const signature = c.req.header('X-Worker-Signature');
  if (signature && WORKER_PUBLIC_KEY) {
    const body = await c.req.text();
    const messageToSign = body; // Sign the raw request body
    
    const isValid = verifySignature(messageToSign, signature, WORKER_PUBLIC_KEY);
    
    if (!isValid) {
      return c.json({ code: 'INVALID_SIGNATURE', message: 'Worker signature verification failed' }, 401);
    }
    
    // Store parsed body for route handler
    c.set('workerBody', JSON.parse(body));
  }
  
  await next();
}

/**
 * Verify Ed25519 signature
 */
function verifySignature(message: string, signatureBase64: string, publicKeyHex: string): boolean {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = decodeBase64(signatureBase64);
    const publicKeyBytes = hexToBytes(publicKeyHex);
    
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Webhook bridge metadata structure
 */
export type WebhookBridgeMetadata = {
  sender: string;           // Sender alias (unhashed, for display)
  senderHash: string;       // Hashed sender for privacy
  title: string;            // Webhook title
  originalTimestamp?: string; // Original timestamp from webhook
};

/**
 * Process inbound webhook from worker
 * 
 * Flow:
 * 1. Worker receives webhook POST with authToken verification
 * 2. Worker encrypts payload for user's edge X25519 key
 * 3. Worker forwards to this endpoint with encrypted package
 * 4. Server stores message, creates/updates conversation
 * 5. SSE notifies user instantly
 */
webhookRoutes.post('/inbound', workerAuthMiddleware, async (c) => {
  type InboundBody = {
    edgeId: string;              // Target webhook edge
    sender: string;              // Sender alias (e.g., "github-ci", "stripe-billing")
    senderHash: string;          // Hash of sender for conversation matching
    encryptedPayload: string;    // Webhook payload encrypted for user (zero-knowledge)
    encryptedMetadata?: string;  // Encrypted sender info for conversation list display
    receivedAt: string;          // When webhook was received
  };
  
  const body: InboundBody = (c as any).get('workerBody') || await c.req.json<InboundBody>();

  if (!body.edgeId || !body.sender || !body.senderHash || !body.encryptedPayload) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Verify edge exists and is active
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, body.edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.status !== 'active') {
    return c.json({ code: 'EDGE_DISABLED', message: 'Edge is disabled' }, 410);
  }

  if (edge.type !== 'webhook') {
    return c.json({ code: 'INVALID_EDGE_TYPE', message: 'Edge is not a webhook edge' }, 400);
  }

  // Look for existing conversation with this sender through this edge
  const existingConv = await db
    .select({ conversationId: conversationParticipants.conversationId })
    .from(conversationParticipants)
    .innerJoin(conversations, eq(conversations.id, conversationParticipants.conversationId))
    .where(and(
      eq(conversations.edgeId, body.edgeId),
      eq(conversationParticipants.externalId, body.senderHash)
    ))
    .limit(1);

  let conversationId: string;

  if (existingConv.length > 0) {
    conversationId = existingConv[0].conversationId;
  } else {
    // Create new conversation
    conversationId = ulid();
    const now = new Date();

    await db.insert(conversations).values({
      id: conversationId,
      origin: 'webhook',
      edgeId: body.edgeId,
      securityLevel: 'gateway_secured',
      encryptedMetadata: body.encryptedMetadata || null,  // Encrypted sender info
      createdAt: now,
      lastActivityAt: now,
    });

    // Add owner as participant
    await db.insert(conversationParticipants).values({
      conversationId,
      edgeId: body.edgeId,
      isOwner: true,
    });

    // Add sender as external participant
    await db.insert(conversationParticipants).values({
      conversationId,
      externalId: body.senderHash,
      displayName: body.sender,  // Store plaintext sender alias for display
    });
  }

  // Create message with encrypted payload
  const messageId = ulid();
  const now = new Date();

  await db.insert(messages).values({
    id: messageId,
    protocolVersion: '1.0',
    conversationId,
    edgeId: body.edgeId,
    origin: 'webhook',
    securityLevel: 'gateway_secured',
    contentType: 'application/encrypted',
    senderExternalId: body.senderHash,
    encryptedContent: body.encryptedPayload,
    nonce: null,
    createdAt: now,
  });

  // Store bridge-specific metadata
  await db.insert(bridgeMessages).values({
    messageId,
    bridgeType: 'webhook',
    senderExternalId: body.senderHash,
    senderDisplayName: body.sender,  // Plaintext sender alias
    platformMessageId: null,  // Webhooks don't have external message IDs
    metadata: {
      sender: body.sender,
      senderHash: body.senderHash,
      title: 'Webhook Notification',  // Will be overwritten by decrypted content
      originalTimestamp: body.receivedAt,
    } as WebhookBridgeMetadata,
  });

  // Update conversation last activity
  await db
    .update(conversations)
    .set({ lastActivityAt: now })
    .where(eq(conversations.id, conversationId));

  // Update edge message count
  await db
    .update(edges)
    .set({ 
      messageCount: edge.messageCount + 1,
      lastActivityAt: now,
    })
    .where(eq(edges.id, body.edgeId));

  // Invalidate conversation cache
  await invalidateCache(`conversations:*`);
  
  // Publish SSE event to edge channel (instant notification)
  await publish(`edge:${body.edgeId}:updates`, {
    type: 'conversation_update',
    payload: {
      conversationId,
      messageId,
      timestamp: now.toISOString(),
    },
  });

  return c.json({
    conversationId,
    messageId,
    isNewConversation: existingConv.length === 0,
  }, 201);
});
