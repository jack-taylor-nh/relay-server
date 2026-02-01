/**
 * Message Routes
 * 
 * POST /v1/messages/send-native - Send a native Relay-to-Relay message
 */

import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { handles, identities, edges, conversations, conversationParticipants, messages } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { randomUUID } from 'crypto';

export const messageRoutes = new Hono();

// All message routes require authentication
messageRoutes.use('*', authMiddleware);

/**
 * POST /v1/messages/send-native
 * Send a native Relay-to-Relay E2EE message by handle
 */
messageRoutes.post('/send-native', async (c) => {
  const senderIdentityId = c.get('identityId') as string;
  
  const body = await c.req.json();
  const { 
    recipientHandle,
    senderHandle,
    ciphertext,
    ephemeralPubkey,
    nonce,
    signature,
    contentType = 'text/plain'
  } = body;

  // Validate required fields
  if (!recipientHandle || !senderHandle || !ciphertext || !ephemeralPubkey || !nonce || !signature) {
    return c.json({ 
      error: 'Missing required fields: recipientHandle, senderHandle, ciphertext, ephemeralPubkey, nonce, signature' 
    }, 400);
  }

  try {
    // 1. Resolve recipient handle to get their identity and public key
    const recipientResult = await db
      .select({
        handleId: handles.id,
        handle: handles.handle,
        identityId: handles.identityId,
        publicKey: identities.publicKey,
      })
      .from(handles)
      .innerJoin(identities, eq(handles.identityId, identities.id))
      .where(eq(handles.handle, recipientHandle))
      .limit(1);

    if (recipientResult.length === 0) {
      return c.json({ error: 'Recipient handle not found' }, 404);
    }

    const recipient = recipientResult[0];

    // 2. Verify sender owns the sender handle
    const senderHandleResult = await db
      .select({ id: handles.id, handle: handles.handle })
      .from(handles)
      .where(and(
        eq(handles.handle, senderHandle),
        eq(handles.identityId, senderIdentityId)
      ))
      .limit(1);

    if (senderHandleResult.length === 0) {
      return c.json({ error: 'You do not own the sender handle' }, 403);
    }

    const senderHandleId = senderHandleResult[0].id;

    // 3. Find or create native edge for sender
    let senderEdge = await db
      .select()
      .from(edges)
      .where(and(
        eq(edges.identityId, senderIdentityId),
        eq(edges.handleId, senderHandleId),
        eq(edges.isNative, true)
      ))
      .limit(1);

    if (senderEdge.length === 0) {
      // Create native edge for sender
      const [newEdge] = await db.insert(edges).values({
        id: randomUUID(),
        identityId: senderIdentityId,
        handleId: senderHandleId,
        type: 'native',
        bridgeType: 'native',
        isNative: true,
        metadata: {},
        address: senderHandle,
        status: 'active',
        securityLevel: 'e2ee',
        createdAt: new Date(),
      }).returning();
      senderEdge = [newEdge];
    }

    const senderEdgeId = senderEdge[0].id;

    // 4. Find or create conversation between sender and recipient
    // Look for existing conversation with both participants
    const existingConversations = await db
      .select({ conversationId: conversationParticipants.conversationId })
      .from(conversationParticipants)
      .where(eq(conversationParticipants.identityId, senderIdentityId));

    let conversationId: string | null = null;

    for (const conv of existingConversations) {
      const participants = await db
        .select({ identityId: conversationParticipants.identityId })
        .from(conversationParticipants)
        .where(eq(conversationParticipants.conversationId, conv.conversationId));

      const participantIds = participants.map(p => p.identityId);
      
      // Check if this conversation has exactly these two participants
      if (participantIds.length === 2 && 
          participantIds.includes(senderIdentityId) && 
          participantIds.includes(recipient.identityId)) {
        conversationId = conv.conversationId;
        break;
      }
    }

    // Create conversation if it doesn't exist
    if (!conversationId) {
      conversationId = ulid();
      const now = new Date();

      await db.insert(conversations).values({
        id: conversationId,
        edgeId: senderEdgeId,
        origin: 'native',
        securityLevel: 'e2ee',
        channelLabel: `@${recipientHandle}`,
        lastActivityAt: now,
        createdAt: now,
      });

      // Add both participants
      await db.insert(conversationParticipants).values([
        {
          conversationId,
          identityId: senderIdentityId,
          joinedAt: now,
        },
        {
          conversationId,
          identityId: recipient.identityId,
          joinedAt: now,
        },
      ]);
    }

    // 5. Create the message
    const messageId = ulid();
    const now = new Date();

    await db.insert(messages).values({
      id: messageId,
      protocolVersion: '1.0',
      conversationId,
      edgeId: senderEdgeId,
      origin: 'native',
      securityLevel: 'e2ee',
      contentType,
      senderIdentityId,
      senderExternalId: null,
      ciphertext,
      ephemeralPubkey,
      nonce,
      signature,
      encryptedContent: null,
      plaintextContent: null,
      createdAt: now,
    });

    // 6. Update conversation last activity
    await db
      .update(conversations)
      .set({ lastActivityAt: now })
      .where(eq(conversations.id, conversationId));

    return c.json({
      messageId,
      conversationId,
      recipientPublicKey: recipient.publicKey,
      createdAt: now.toISOString(),
    }, 201);

  } catch (error) {
    console.error('Error sending native message:', error);
    return c.json({ error: 'Failed to send message' }, 500);
  }
});

export default messageRoutes;
