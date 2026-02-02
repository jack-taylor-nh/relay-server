/**
 * Message Routes
 * 
 * POST /v1/messages - Send a message (unified endpoint for all conversation types)
 * POST /v1/messages/send-native - Send a native Relay-to-Relay message (LEGACY)
 */

import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { handles, identities, edges, conversations, conversationParticipants, messages, type SecurityLevel } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { randomUUID } from 'crypto';

export const messageRoutes = new Hono();

// All message routes require authentication
messageRoutes.use('*', authMiddleware);

/**
 * POST /v1/messages
 * Unified message sending endpoint for all conversation types (native, email, Discord, etc.)
 * 
 * Accepts MessageEnvelope structure:
 * {
 *   protocol_version: "1.0",
 *   message_id: string,
 *   conversation_id: string,
 *   edge_id: string,
 *   origin: EdgeType,
 *   security_level: "e2ee" | "gateway_secured",
 *   payload: {
 *     content_type: string,
 *     ratchet: EncryptedRatchetMessage
 *   },
 *   created_at: string,
 *   signature?: string
 * }
 */
messageRoutes.post('/', async (c) => {
  const senderIdentityId = c.get('identityId') as string;
  
  const envelope = await c.req.json<{
    protocol_version: string;
    message_id: string;
    conversation_id: string;
    edge_id: string;
    origin: string;
    security_level: SecurityLevel;
    payload: {
      content_type: string;
      ratchet: {
        ciphertext: string;
        dh: string;
        pn: number;
        n: number;
        nonce: string;
      };
    };
    created_at: string;
    signature?: string;
  }>();

  // Validate required fields
  if (!envelope.message_id || !envelope.conversation_id || !envelope.edge_id || 
      !envelope.payload?.ratchet) {
    return c.json({ 
      error: 'Invalid message envelope: missing required fields' 
    }, 400);
  }

  try {
    // 1. Verify conversation exists and user is a participant
    const [conversation] = await db
      .select()
      .from(conversations)
      .where(eq(conversations.id, envelope.conversation_id))
      .limit(1);

    if (!conversation) {
      return c.json({ error: 'Conversation not found' }, 404);
    }

    const [participation] = await db
      .select()
      .from(conversationParticipants)
      .where(and(
        eq(conversationParticipants.conversationId, envelope.conversation_id),
        eq(conversationParticipants.identityId, senderIdentityId)
      ))
      .limit(1);

    if (!participation) {
      return c.json({ error: 'Not a participant in this conversation' }, 403);
    }

    // 2. Verify sender owns the edge
    const [edge] = await db
      .select()
      .from(edges)
      .where(and(
        eq(edges.id, envelope.edge_id),
        eq(edges.identityId, senderIdentityId)
      ))
      .limit(1);

    if (!edge) {
      return c.json({ error: 'Edge not found or not owned by sender' }, 403);
    }

    // 3. Store message with ratchet data
    const [message] = await db.insert(messages).values({
      id: envelope.message_id,
      protocolVersion: envelope.protocol_version,
      conversationId: envelope.conversation_id,
      edgeId: envelope.edge_id,
      origin: envelope.origin,
      securityLevel: envelope.security_level,
      contentType: envelope.payload.content_type,
      senderIdentityId,
      // Store ratchet fields for e2ee
      ciphertext: envelope.payload.ratchet.ciphertext,
      ephemeralPubkey: envelope.payload.ratchet.dh,
      nonce: envelope.payload.ratchet.nonce,
      signature: envelope.signature || null,
      // Store ratchet metadata (pn, n) as JSON in a new field if needed
      // For now, we rely on the ratchet state being managed client-side
      plaintextContent: null, // Never store plaintext
      encryptedContent: null, // Worker will handle if needed
      createdAt: new Date(envelope.created_at),
    }).returning();

    // 4. Update conversation activity
    await db
      .update(conversations)
      .set({ lastActivityAt: new Date(envelope.created_at) })
      .where(eq(conversations.id, envelope.conversation_id));

    // 5. Route based on origin type
    // For gateway_secured messages (email, Discord, etc.), forward to appropriate worker
    if (envelope.security_level === 'gateway_secured') {
      if (envelope.origin === 'email') {
        // Forward to email worker for ratchet decryption and email bridging
        try {
          const emailWorkerUrl = process.env.EMAIL_WORKER_URL || 'https://email-worker.relay.workers.dev';
          
          // TODO: Get conversation details for recipient and subject
          const workerPayload = {
            conversationId: envelope.conversation_id,
            envelope: envelope,
            encryptedRecipient: '[TODO: encrypted recipient]',
            edgeAddress: '[TODO: edge address]',
            subject: 'Message from Relay',
            inReplyTo: undefined,
          };
          
          const workerResponse = await fetch(`${emailWorkerUrl}/api/send-ratchet`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Worker ${process.env.WORKER_SECRET || 'dev-worker-secret'}`,
            },
            body: JSON.stringify(workerPayload),
          });
          
          if (!workerResponse.ok) {
            console.error('Email worker forward failed:', await workerResponse.text());
            // Don't fail the message storage - worker can retry later
          }
        } catch (error) {
          console.error('Error forwarding to email worker:', error);
          // Don't fail - message is stored, worker can process later
        }
      }
      // TODO: Add Discord, SMS, Telegram bridges
      console.log(`Gateway message for origin: ${envelope.origin} - stored for worker processing`);
    }

    return c.json({
      success: true,
      message_id: message.id,
      conversation_id: message.conversationId,
      created_at: message.createdAt.toISOString(),
    });

  } catch (error: any) {
    console.error('Error sending unified message:', error);
    return c.json({ error: 'Failed to send message', details: error.message }, 500);
  }
});


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
        // eq(edges.handleId, senderHandleId),  // Deprecated - removed in zero-knowledge refactor
        eq(edges.address, senderHandle),  // Match by address instead
        eq(edges.isNative, true)
      ))
      .limit(1);

    if (senderEdge.length === 0) {
      // Create native edge for sender
      const { computeQueryKey } = await import('../lib/queryKey.js');
      const ownerQueryKey = computeQueryKey(senderIdentityId);
      
      const [newEdge] = await db.insert(edges).values({
        id: randomUUID(),
        identityId: senderIdentityId,
        ownerQueryKey,
        // handleId: senderHandleId,  // Deprecated - removed in zero-knowledge refactor
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
        channelLabel: `&${recipientHandle}`,
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
    console.error('Error sending native message:', { code: (error as any).code, message: 'Failed to send message' });
    return c.json({ error: 'Failed to send message' }, 500);
  }
});

export default messageRoutes;
