/**
 * Conversation Routes
 * 
 * GET /v1/conversations - List conversations
 * GET /v1/conversations/:id/messages - List messages in a conversation
 * POST /v1/conversations/:id/messages - Send a message
 */

import { Hono } from 'hono';
import { eq, desc, and, lt, sql, inArray } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db, conversations, conversationParticipants, messages, edges, handles, type SecurityLevel } from '../db/index.js';
import { authMiddleware } from '../middleware/auth.js';
import { DEFAULT_PAGE_SIZE } from '../core/constants.js';

export const conversationRoutes = new Hono();

// All conversation routes require authentication
conversationRoutes.use('*', authMiddleware);

/**
 * List conversations for the authenticated user
 */
conversationRoutes.get('/', async (c) => {
  const identityId = c.get('fingerprint'); // fingerprint = identityId
  const cursor = c.req.query('cursor');
  const limit = Math.min(parseInt(c.req.query('limit') || String(DEFAULT_PAGE_SIZE), 10), 100);

  // Get conversation IDs for this user (where they are a participant)
  const participations = await db
    .select({ conversationId: conversationParticipants.conversationId })
    .from(conversationParticipants)
    .where(eq(conversationParticipants.identityId, identityId));

  const conversationIds = participations.map(p => p.conversationId);

  if (conversationIds.length === 0) {
    return c.json({ conversations: [], cursor: null });
  }

  // Get conversations with pagination
  let query = db
    .select()
    .from(conversations)
    .where(inArray(conversations.id, conversationIds))
    .orderBy(desc(conversations.lastActivityAt))
    .limit(limit + 1);

  if (cursor) {
    query = db
      .select()
      .from(conversations)
      .where(and(
        inArray(conversations.id, conversationIds),
        lt(conversations.lastActivityAt, new Date(cursor))
      ))
      .orderBy(desc(conversations.lastActivityAt))
      .limit(limit + 1);
  }

  const results = await query;
  
  const hasMore = results.length > limit;
  const items = hasMore ? results.slice(0, -1) : results;
  const nextCursor = hasMore ? items[items.length - 1].lastActivityAt.toISOString() : null;

  // Get participants and edge info for each conversation
  const conversationsWithDetails = await Promise.all(
    items.map(async (conv) => {
      const parts = await db
        .select()
        .from(conversationParticipants)
        .where(eq(conversationParticipants.conversationId, conv.id));

      // Get edge info if applicable
      let edge = null;
      if (conv.edgeId) {
        const [edgeResult] = await db
          .select({ id: edges.id, type: edges.type, address: edges.address, label: edges.label, status: edges.status })
          .from(edges)
          .where(eq(edges.id, conv.edgeId))
          .limit(1);
        edge = edgeResult || null;
      }

      // Find counterparty
      const counterparty = parts.find(p => p.identityId !== identityId);
      
      // For native conversations, get counterparty's handle
      let counterpartyHandle = null;
      if (conv.origin === 'native' && counterparty?.identityId) {
        const [handleResult] = await db
          .select({ handle: handles.handle, displayName: handles.displayName })
          .from(handles)
          .where(eq(handles.identityId, counterparty.identityId))
          .limit(1);
        if (handleResult) {
          counterpartyHandle = handleResult.handle;
        }
      }
      
      return {
        id: conv.id,
        origin: conv.origin,
        securityLevel: conv.securityLevel,
        channelLabel: conv.channelLabel,
        edge: edge ? {
          id: edge.id,
          type: edge.type,
          address: edge.address,
          label: edge.label,
          status: edge.status,
        } : null,
        counterparty: counterparty ? {
          identityId: counterparty.identityId,
          externalId: counterparty.externalId,
          displayName: counterparty.displayName,
          handle: counterpartyHandle,
        } : null,
        lastActivityAt: conv.lastActivityAt.toISOString(),
        createdAt: conv.createdAt.toISOString(),
      };
    })
  );

  return c.json({
    conversations: conversationsWithDetails,
    cursor: nextCursor,
  });
});

/**
 * Get messages in a conversation
 */
conversationRoutes.get('/:id/messages', async (c) => {
  const identityId = c.get('fingerprint');
  const conversationId = c.req.param('id');
  const cursor = c.req.query('cursor');
  const limit = Math.min(parseInt(c.req.query('limit') || String(DEFAULT_PAGE_SIZE), 10), 100);

  // Verify user is a participant
  const [participation] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, conversationId),
      eq(conversationParticipants.identityId, identityId)
    ))
    .limit(1);

  if (!participation) {
    return c.json({ code: 'NOT_FOUND', message: 'Conversation not found' }, 404);
  }

  // Get conversation to know security level
  const [conversation] = await db
    .select({ securityLevel: conversations.securityLevel })
    .from(conversations)
    .where(eq(conversations.id, conversationId))
    .limit(1);

  // Get messages with pagination
  let query = db
    .select()
    .from(messages)
    .where(eq(messages.conversationId, conversationId))
    .orderBy(desc(messages.createdAt))
    .limit(limit + 1);

  if (cursor) {
    query = db
      .select()
      .from(messages)
      .where(and(
        eq(messages.conversationId, conversationId),
        lt(messages.createdAt, new Date(cursor))
      ))
      .orderBy(desc(messages.createdAt))
      .limit(limit + 1);
  }

  const results = await query;
  
  const hasMore = results.length > limit;
  const items = hasMore ? results.slice(0, -1) : results;
  const nextCursor = hasMore ? items[items.length - 1].createdAt.toISOString() : null;

  return c.json({
    securityLevel: conversation?.securityLevel || 'gateway_secured',
    messages: items.map(msg => ({
      id: msg.id,
      protocolVersion: msg.protocolVersion,
      conversationId: msg.conversationId,
      edgeId: msg.edgeId,
      origin: msg.origin,
      securityLevel: msg.securityLevel,
      contentType: msg.contentType,
      senderIdentityId: msg.senderIdentityId,
      senderExternalId: msg.senderExternalId,
      // E2EE fields (native Relay-to-Relay)
      ciphertext: msg.ciphertext,
      ephemeralPubkey: msg.ephemeralPubkey,
      nonce: msg.nonce,
      signature: msg.signature,
      // Double Ratchet fields
      ratchetPn: msg.ratchetPn,
      ratchetN: msg.ratchetN,
      // Zero-knowledge encrypted payload (from worker)
      encryptedContent: msg.encryptedContent,
      // Gateway secured field (DEPRECATED)
      plaintextContent: msg.plaintextContent,
      createdAt: msg.createdAt.toISOString(),
    })),
    cursor: nextCursor,
  });
});

/**
 * Send a message in a conversation
 */
conversationRoutes.post('/:id/messages', async (c) => {
  const identityId = c.get('fingerprint');
  const conversationId = c.req.param('id');
  
  const body = await c.req.json<{
    // Protocol fields
    protocolVersion?: string;
    contentType?: string;
    securityLevel?: SecurityLevel;
    // E2EE message
    ciphertext?: string;
    ephemeralPubkey?: string;
    nonce?: string;
    signature?: string;
    // Gateway secured message
    plaintextContent?: string;
  }>();

  const protocolVersion = body.protocolVersion || '1.0';
  const contentType = body.contentType || 'text/plain';

  // Verify user is a participant
  const [participation] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, conversationId),
      eq(conversationParticipants.identityId, identityId)
    ))
    .limit(1);

  if (!participation) {
    return c.json({ code: 'NOT_FOUND', message: 'Conversation not found' }, 404);
  }

  // Get conversation details (security level, origin, edgeId)
  const [conversation] = await db
    .select({ 
      securityLevel: conversations.securityLevel,
      origin: conversations.origin,
      edgeId: conversations.edgeId,
    })
    .from(conversations)
    .where(eq(conversations.id, conversationId))
    .limit(1);

  // Determine message security level based on content
  let messageSecurityLevel: SecurityLevel;
  if (body.ciphertext && body.ephemeralPubkey && body.nonce) {
    messageSecurityLevel = 'e2ee';
    if (!body.signature) {
      return c.json({ code: 'VALIDATION_ERROR', message: 'E2EE messages require signature' }, 400);
    }
  } else if (body.plaintextContent) {
    messageSecurityLevel = 'gateway_secured';
  } else {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Message content required (ciphertext or plaintextContent)' }, 400);
  }

  // Check if we need to update conversation security level to 'mixed'
  const currentConvSecurityLevel = conversation.securityLevel;
  let newConvSecurityLevel = currentConvSecurityLevel;
  if (currentConvSecurityLevel !== 'mixed' && currentConvSecurityLevel !== messageSecurityLevel) {
    newConvSecurityLevel = 'mixed';
  }

  // Create message
  const messageId = ulid();
  const now = new Date();

  await db.insert(messages).values({
    id: messageId,
    protocolVersion,
    conversationId,
    edgeId: conversation.edgeId,
    origin: conversation.origin,
    securityLevel: messageSecurityLevel,
    contentType,
    senderIdentityId: identityId,
    ciphertext: body.ciphertext,
    ephemeralPubkey: body.ephemeralPubkey,
    nonce: body.nonce,
    signature: body.signature,
    plaintextContent: body.plaintextContent,
    createdAt: now,
  });

  // Update conversation last activity (and security level if changed)
  await db
    .update(conversations)
    .set({ 
      lastActivityAt: now,
      ...(newConvSecurityLevel !== currentConvSecurityLevel && { securityLevel: newConvSecurityLevel }),
    })
    .where(eq(conversations.id, conversationId));

  return c.json({
    id: messageId,
    conversationId,
    senderIdentityId: identityId,
    createdAt: now.toISOString(),
  }, 201);
});
