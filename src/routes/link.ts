/**
 * Contact Link Routes
 * 
 * Public endpoints for Contact Link visitor interactions.
 * These routes are UNAUTHENTICATED - visitors don't have Relay identities.
 * 
 * Endpoints:
 * - GET /v1/link/:linkId - Get link info + prekey bundle for key exchange
 * - POST /v1/link/:linkId/session - Create/restore visitor session
 * - GET /v1/link/:linkId/session/:visitorPubKey - Get session + encrypted ratchet state
 * - POST /v1/link/:linkId/messages - Send message (visitor → relay user)
 * - GET /v1/link/:linkId/messages/:visitorPubKey - Poll for messages (relay user → visitor)
 * - PUT /v1/link/:linkId/session/:visitorPubKey/ratchet - Update encrypted ratchet state
 */

import { Hono } from 'hono';
import { eq, and, desc } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { 
  edges, 
  visitorSessions, 
  conversations, 
  conversationParticipants, 
  messages,
  type SecurityLevel 
} from '../db/schema.js';

export const linkRoutes = new Hono();

// Rate limiting constants
const MAX_PIN_ATTEMPTS = 3;
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

/**
 * GET /v1/link/:linkId
 * Get contact link info and prekey bundle for X3DH key exchange.
 * This is public - anyone with the link can access.
 */
linkRoutes.get('/:linkId', async (c) => {
  const linkId = c.req.param('linkId');
  
  // Find the contact link edge by its address (slug)
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  // Return public info needed for key exchange
  return c.json({
    linkId: edge.address,
    edgeId: edge.id,
    // X25519 public key for the contact link (needed for X3DH/encryption)
    x25519PublicKey: edge.x25519PublicKey,
    // Label is encrypted, only the owner can read it
    // We don't expose it to visitors
    createdAt: edge.createdAt?.toISOString(),
  });
});

/**
 * POST /v1/link/:linkId/session
 * Create a new visitor session or restore existing one.
 * 
 * Body:
 * {
 *   visitorPublicKey: string,  // Derived from PIN + linkId
 *   displayName?: string,      // Optional name for the visitor
 * }
 */
linkRoutes.post('/:linkId/session', async (c) => {
  const linkId = c.req.param('linkId');
  
  const body = await c.req.json<{
    visitorPublicKey: string;
    displayName?: string;
  }>();
  
  if (!body.visitorPublicKey) {
    return c.json({ 
      code: 'INVALID_REQUEST',
      message: 'visitorPublicKey is required' 
    }, 400);
  }
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  // Check for existing session with this public key
  const [existingSession] = await db
    .select()
    .from(visitorSessions)
    .where(and(
      eq(visitorSessions.contactLinkEdgeId, edge.id),
      eq(visitorSessions.visitorPublicKey, body.visitorPublicKey)
    ))
    .limit(1);
  
  if (existingSession) {
    // Rate limiting check
    const now = Date.now();
    const lastAttempt = existingSession.lastAttemptAt?.getTime() || 0;
    const timeSinceLastAttempt = now - lastAttempt;
    
    if (existingSession.failedAttempts >= MAX_PIN_ATTEMPTS && 
        timeSinceLastAttempt < RATE_LIMIT_WINDOW_MS) {
      const waitTime = Math.ceil((RATE_LIMIT_WINDOW_MS - timeSinceLastAttempt) / 1000);
      return c.json({
        code: 'RATE_LIMITED',
        message: `Too many attempts. Please wait ${waitTime} seconds.`,
        retryAfter: waitTime,
      }, 429);
    }
    
    // Reset failed attempts on successful match (same public key = same PIN)
    await db
      .update(visitorSessions)
      .set({ 
        failedAttempts: 0,
        lastAttemptAt: new Date(),
        lastActivityAt: new Date(),
        // Update display name if provided
        displayName: body.displayName || existingSession.displayName,
      })
      .where(eq(visitorSessions.id, existingSession.id));
    
    // Return existing session
    return c.json({
      sessionId: existingSession.id,
      conversationId: existingSession.conversationId,
      encryptedRatchetState: existingSession.encryptedRatchetState,
      displayName: body.displayName || existingSession.displayName,
      isNew: false,
    });
  }
  
  // Create new session
  const sessionId = ulid();
  const now = new Date();
  
  // Create conversation for this visitor
  const conversationId = ulid();
  
  await db.insert(conversations).values({
    id: conversationId,
    origin: 'contact_link',
    edgeId: edge.id,
    securityLevel: 'e2ee' as SecurityLevel,
    createdAt: now,
    lastActivityAt: now,
  });
  
  // Add participants
  // 1. The contact link edge owner
  await db.insert(conversationParticipants).values({
    conversationId,
    edgeId: edge.id,
    isOwner: true,
    joinedAt: now,
  });
  
  // 2. The visitor (external participant)
  await db.insert(conversationParticipants).values({
    conversationId,
    externalId: body.visitorPublicKey,
    displayName: body.displayName || 'Anonymous',
    isOwner: false,
    joinedAt: now,
  });
  
  // Create the session
  await db.insert(visitorSessions).values({
    id: sessionId,
    contactLinkEdgeId: edge.id,
    visitorPublicKey: body.visitorPublicKey,
    displayName: body.displayName || null,
    conversationId,
    failedAttempts: 0,
    createdAt: now,
    lastActivityAt: now,
  });
  
  return c.json({
    sessionId,
    conversationId,
    encryptedRatchetState: null, // New session, no state yet
    displayName: body.displayName || null,
    isNew: true,
  }, 201);
});

/**
 * GET /v1/link/:linkId/session/:visitorPubKey
 * Get session info and encrypted ratchet state.
 * Used when visitor returns and wants to check if session exists.
 */
linkRoutes.get('/:linkId/session/:visitorPubKey', async (c) => {
  const linkId = c.req.param('linkId');
  const visitorPubKey = decodeURIComponent(c.req.param('visitorPubKey'));
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  const [session] = await db
    .select()
    .from(visitorSessions)
    .where(and(
      eq(visitorSessions.contactLinkEdgeId, edge.id),
      eq(visitorSessions.visitorPublicKey, visitorPubKey)
    ))
    .limit(1);
  
  if (!session) {
    return c.json({ 
      code: 'SESSION_NOT_FOUND',
      message: 'No session found for this visitor' 
    }, 404);
  }
  
  return c.json({
    sessionId: session.id,
    conversationId: session.conversationId,
    encryptedRatchetState: session.encryptedRatchetState,
    displayName: session.displayName,
    createdAt: session.createdAt?.toISOString(),
    lastActivityAt: session.lastActivityAt?.toISOString(),
  });
});

/**
 * PUT /v1/link/:linkId/session/:visitorPubKey/ratchet
 * Update encrypted ratchet state after sending/receiving messages.
 * 
 * Body:
 * {
 *   encryptedRatchetState: string,  // Encrypted with visitor's PIN-derived key
 * }
 */
linkRoutes.put('/:linkId/session/:visitorPubKey/ratchet', async (c) => {
  const linkId = c.req.param('linkId');
  const visitorPubKey = decodeURIComponent(c.req.param('visitorPubKey'));
  
  const body = await c.req.json<{
    encryptedRatchetState: string;
  }>();
  
  if (!body.encryptedRatchetState) {
    return c.json({ 
      code: 'INVALID_REQUEST',
      message: 'encryptedRatchetState is required' 
    }, 400);
  }
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  const [session] = await db
    .select()
    .from(visitorSessions)
    .where(and(
      eq(visitorSessions.contactLinkEdgeId, edge.id),
      eq(visitorSessions.visitorPublicKey, visitorPubKey)
    ))
    .limit(1);
  
  if (!session) {
    return c.json({ 
      code: 'SESSION_NOT_FOUND',
      message: 'No session found for this visitor' 
    }, 404);
  }
  
  await db
    .update(visitorSessions)
    .set({
      encryptedRatchetState: body.encryptedRatchetState,
      lastActivityAt: new Date(),
    })
    .where(eq(visitorSessions.id, session.id));
  
  return c.json({ success: true });
});

/**
 * POST /v1/link/:linkId/messages
 * Send a message from visitor to relay user.
 * 
 * Body:
 * {
 *   visitorPublicKey: string,
 *   payload: {
 *     ciphertext: string,
 *     ephemeralPubkey: string,  // DH ratchet key
 *     nonce: string,
 *     pn: number,               // Previous chain length
 *     n: number,                // Message number in chain
 *   },
 *   encryptedRatchetState?: string,  // Optional: update state atomically
 * }
 */
linkRoutes.post('/:linkId/messages', async (c) => {
  const linkId = c.req.param('linkId');
  
  const body = await c.req.json<{
    visitorPublicKey: string;
    payload: {
      ciphertext: string;
      ephemeralPubkey: string;
      nonce: string;
      pn?: number;
      n?: number;
    };
    encryptedRatchetState?: string;
  }>();
  
  if (!body.visitorPublicKey || !body.payload?.ciphertext) {
    return c.json({ 
      code: 'INVALID_REQUEST',
      message: 'visitorPublicKey and payload.ciphertext are required' 
    }, 400);
  }
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  // Find visitor session
  const [session] = await db
    .select()
    .from(visitorSessions)
    .where(and(
      eq(visitorSessions.contactLinkEdgeId, edge.id),
      eq(visitorSessions.visitorPublicKey, body.visitorPublicKey)
    ))
    .limit(1);
  
  if (!session || !session.conversationId) {
    return c.json({ 
      code: 'SESSION_NOT_FOUND',
      message: 'No session found. Please create a session first.' 
    }, 404);
  }
  
  const now = new Date();
  const messageId = ulid();
  
  // Insert message
  await db.insert(messages).values({
    id: messageId,
    protocolVersion: '1.0',
    conversationId: session.conversationId,
    edgeId: edge.id,
    origin: 'contact_link',
    securityLevel: 'e2ee',
    contentType: 'application/encrypted',
    senderExternalId: body.visitorPublicKey,
    ciphertext: body.payload.ciphertext,
    ephemeralPubkey: body.payload.ephemeralPubkey,
    nonce: body.payload.nonce,
    ratchetPn: body.payload.pn ?? null,
    ratchetN: body.payload.n ?? null,
    createdAt: now,
  });
  
  // Update conversation activity
  await db
    .update(conversations)
    .set({ lastActivityAt: now })
    .where(eq(conversations.id, session.conversationId));
  
  // Update edge message count and activity
  await db
    .update(edges)
    .set({ 
      messageCount: (edge.messageCount || 0) + 1,
      lastActivityAt: now,
    })
    .where(eq(edges.id, edge.id));
  
  // Update session activity + optional ratchet state
  const sessionUpdate: { lastActivityAt: Date; encryptedRatchetState?: string } = {
    lastActivityAt: now,
  };
  if (body.encryptedRatchetState) {
    sessionUpdate.encryptedRatchetState = body.encryptedRatchetState;
  }
  await db
    .update(visitorSessions)
    .set(sessionUpdate)
    .where(eq(visitorSessions.id, session.id));
  
  return c.json({
    messageId,
    conversationId: session.conversationId,
    createdAt: now.toISOString(),
  }, 201);
});

/**
 * GET /v1/link/:linkId/messages/:visitorPubKey
 * Poll for messages from relay user to visitor.
 * Only returns messages NOT sent by the visitor.
 * 
 * Query params:
 * - since: ISO timestamp to get messages after
 * - limit: Max messages to return (default 50)
 */
linkRoutes.get('/:linkId/messages/:visitorPubKey', async (c) => {
  const linkId = c.req.param('linkId');
  const visitorPubKey = decodeURIComponent(c.req.param('visitorPubKey'));
  const since = c.req.query('since');
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found or has been disabled' 
    }, 404);
  }
  
  // Find visitor session
  const [session] = await db
    .select()
    .from(visitorSessions)
    .where(and(
      eq(visitorSessions.contactLinkEdgeId, edge.id),
      eq(visitorSessions.visitorPublicKey, visitorPubKey)
    ))
    .limit(1);
  
  if (!session || !session.conversationId) {
    return c.json({ 
      code: 'SESSION_NOT_FOUND',
      message: 'No session found for this visitor' 
    }, 404);
  }
  
  // Get messages for this conversation
  // Filter out messages sent by the visitor (they already have those)
  let query = db
    .select()
    .from(messages)
    .where(
      eq(messages.conversationId, session.conversationId)
    )
    .orderBy(desc(messages.createdAt))
    .limit(limit);
  
  const allMessages = await query;
  
  // Filter to messages from the Relay user (not the visitor)
  // and optionally filter by 'since' timestamp
  const filteredMessages = allMessages.filter(msg => {
    // Exclude visitor's own messages
    if (msg.senderExternalId === visitorPubKey) return false;
    // Filter by timestamp if provided
    if (since && msg.createdAt) {
      return msg.createdAt > new Date(since);
    }
    return true;
  });
  
  // Update session activity
  await db
    .update(visitorSessions)
    .set({ lastActivityAt: new Date() })
    .where(eq(visitorSessions.id, session.id));
  
  return c.json({
    messages: filteredMessages.map(msg => ({
      id: msg.id,
      ciphertext: msg.ciphertext,
      ephemeralPubkey: msg.ephemeralPubkey,
      nonce: msg.nonce,
      pn: msg.ratchetPn,
      n: msg.ratchetN,
      createdAt: msg.createdAt?.toISOString(),
    })),
    conversationId: session.conversationId,
  });
});

/**
 * POST /v1/link/:linkId/session/verify
 * Record a failed PIN attempt for rate limiting.
 * Called when visitor's derived key doesn't match any session.
 * 
 * Body:
 * {
 *   visitorPublicKey: string,  // The incorrect key that was tried
 * }
 */
linkRoutes.post('/:linkId/session/verify', async (c) => {
  const linkId = c.req.param('linkId');
  
  const body = await c.req.json<{
    visitorPublicKey: string;
  }>();
  
  // Find the contact link edge
  const [edge] = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.type, 'contact_link'),
      eq(edges.address, linkId),
      eq(edges.status, 'active')
    ))
    .limit(1);
  
  if (!edge) {
    return c.json({ 
      code: 'LINK_NOT_FOUND',
      message: 'Contact link not found' 
    }, 404);
  }
  
  // This is informational - we can't really track failed attempts
  // without a session. The rate limiting is per-session once created.
  // For now, just acknowledge the request.
  return c.json({ 
    code: 'SESSION_NOT_FOUND',
    message: 'No matching session found' 
  }, 404);
});
