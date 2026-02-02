/**
 * Message Routes
 * 
 * POST /v1/messages - Send a message (unified endpoint for all conversation types)
 */

import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { handles, identities, edges, conversations, conversationParticipants, messages, type SecurityLevel, type EdgeType } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';

export const messageRoutes = new Hono();

// All message routes require authentication
messageRoutes.use('*', authMiddleware);

/**
 * POST /v1/messages
 * Unified message sending endpoint for all conversation types (native, email, Discord, etc.)
 * 
 * For NEW conversations, provide recipient_handle instead of conversation_id.
 * The server will create the conversation and return the conversation_id.
 * 
 * Request body:
 * {
 *   // Either conversation_id (existing) or recipient_handle (new native conversation)
 *   conversation_id?: string,
 *   recipient_handle?: string,  // For new native conversations
 *   
 *   edge_id: string,            // Sender's edge
 *   origin: "native" | "email" | etc,
 *   security_level: "e2ee" | "gateway_secured",
 *   
 *   payload: {
 *     content_type: string,
 *     ciphertext: string,
 *     ephemeral_pubkey: string,
 *     nonce: string,
 *   },
 *   
 *   signature: string
 * }
 */
messageRoutes.post('/', async (c) => {
  const senderIdentityId = c.get('identityId') as string;
  
  const body = await c.req.json<{
    conversation_id?: string;
    recipient_handle?: string;
    edge_id: string;
    origin: string;
    security_level: SecurityLevel;
    payload: {
      content_type: string;
      ciphertext: string;
      ephemeral_pubkey: string;
      nonce: string;
      // Optional ratchet fields for Double Ratchet protocol
      dh?: string;
      pn?: number;
      n?: number;
    };
    signature: string;
  }>();

  // Validate required fields
  if (!body.edge_id || !body.payload?.ciphertext || !body.payload?.nonce || !body.signature) {
    return c.json({ 
      error: 'Missing required fields: edge_id, payload.ciphertext, payload.nonce, signature' 
    }, 400);
  }

  // Must have either conversation_id or recipient_handle
  if (!body.conversation_id && !body.recipient_handle) {
    return c.json({ 
      error: 'Must provide either conversation_id (existing) or recipient_handle (new conversation)' 
    }, 400);
  }

  try {
    // 1. Verify sender owns the edge
    const [senderEdge] = await db
      .select()
      .from(edges)
      .where(and(
        eq(edges.id, body.edge_id),
        eq(edges.identityId, senderIdentityId)
      ))
      .limit(1);

    if (!senderEdge) {
      return c.json({ error: 'Edge not found or not owned by sender' }, 403);
    }

    let conversationId = body.conversation_id;
    let recipientIdentityId: string | null = null;
    let isNewConversation = false;

    // 2. Handle conversation - either find existing or create new
    if (conversationId) {
      // Existing conversation - verify participation
      const [conversation] = await db
        .select()
        .from(conversations)
        .where(eq(conversations.id, conversationId))
        .limit(1);

      if (!conversation) {
        return c.json({ error: 'Conversation not found' }, 404);
      }

      const [participation] = await db
        .select()
        .from(conversationParticipants)
        .where(and(
          eq(conversationParticipants.conversationId, conversationId),
          eq(conversationParticipants.identityId, senderIdentityId)
        ))
        .limit(1);

      if (!participation) {
        return c.json({ error: 'Not a participant in this conversation' }, 403);
      }
    } else if (body.recipient_handle) {
      // New native conversation - resolve recipient and create conversation
      if (body.origin !== 'native') {
        return c.json({ error: 'recipient_handle is only valid for native origin' }, 400);
      }

      // Resolve recipient - check both handles table and edges table
      // First try edges (new unified model)
      const [recipientEdge] = await db
        .select({
          identityId: edges.identityId,
          address: edges.address,
        })
        .from(edges)
        .where(and(
          eq(edges.address, body.recipient_handle),
          eq(edges.isNative, true),
          eq(edges.status, 'active')
        ))
        .limit(1);

      if (recipientEdge) {
        recipientIdentityId = recipientEdge.identityId;
      } else {
        // Fallback to handles table (legacy)
        const [recipientHandle] = await db
          .select({ identityId: handles.identityId })
          .from(handles)
          .where(eq(handles.handle, body.recipient_handle))
          .limit(1);

        if (!recipientHandle) {
          return c.json({ error: 'Recipient handle not found' }, 404);
        }
        recipientIdentityId = recipientHandle.identityId;
      }

      // Check for existing conversation between these two users
      const senderConversations = await db
        .select({ conversationId: conversationParticipants.conversationId })
        .from(conversationParticipants)
        .where(eq(conversationParticipants.identityId, senderIdentityId));

      for (const conv of senderConversations) {
        const participants = await db
          .select({ identityId: conversationParticipants.identityId })
          .from(conversationParticipants)
          .where(eq(conversationParticipants.conversationId, conv.conversationId));

        const participantIds = participants.map(p => p.identityId);
        
        if (participantIds.length === 2 && 
            participantIds.includes(senderIdentityId) && 
            participantIds.includes(recipientIdentityId)) {
          conversationId = conv.conversationId;
          break;
        }
      }

      // Create new conversation if none exists
      if (!conversationId) {
        conversationId = ulid();
        const now = new Date();
        isNewConversation = true;

        await db.insert(conversations).values({
          id: conversationId,
          edgeId: body.edge_id,
          origin: 'native',
          securityLevel: 'e2ee',
          channelLabel: `&${body.recipient_handle}`,
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
            identityId: recipientIdentityId,
            joinedAt: now,
          },
        ]);
      }
    }

    // 3. Create the message
    const messageId = ulid();
    const now = new Date();

    await db.insert(messages).values({
      id: messageId,
      protocolVersion: '1.0',
      conversationId: conversationId!,
      edgeId: body.edge_id,
      origin: body.origin as EdgeType,
      securityLevel: body.security_level,
      contentType: body.payload.content_type || 'text/plain',
      senderIdentityId,
      senderExternalId: null,
      ciphertext: body.payload.ciphertext,
      ephemeralPubkey: body.payload.ephemeral_pubkey,
      nonce: body.payload.nonce,
      // Double Ratchet fields
      ratchetPn: body.payload.pn ?? null,
      ratchetN: body.payload.n ?? null,
      signature: body.signature,
      encryptedContent: null,
      plaintextContent: null,
      createdAt: now,
    });

    // 4. Update conversation last activity
    await db
      .update(conversations)
      .set({ lastActivityAt: now })
      .where(eq(conversations.id, conversationId!));

    // 5. For gateway_secured messages, forward to appropriate worker
    if (body.security_level === 'gateway_secured') {
      if (body.origin === 'email') {
        try {
          const emailWorkerUrl = process.env.EMAIL_WORKER_URL || 'https://email-worker.relay.workers.dev';
          
          const workerPayload = {
            conversationId: conversationId,
            messageId,
            edgeId: body.edge_id,
            ciphertext: body.payload.ciphertext,
            ephemeralPubkey: body.payload.ephemeral_pubkey,
            nonce: body.payload.nonce,
          };
          
          const workerResponse = await fetch(`${emailWorkerUrl}/api/send`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Worker ${process.env.WORKER_SECRET || 'dev-worker-secret'}`,
            },
            body: JSON.stringify(workerPayload),
          });
          
          if (!workerResponse.ok) {
            console.error('Email worker forward failed:', await workerResponse.text());
          }
        } catch (error) {
          console.error('Error forwarding to email worker:', error);
        }
      }
      console.log(`Gateway message for origin: ${body.origin} - stored for worker processing`);
    }

    // 6. Get recipient public key if this was a new conversation (client needs it for encryption)
    let recipientPublicKey: string | null = null;
    if (recipientIdentityId) {
      const [recipient] = await db
        .select({ publicKey: identities.publicKey })
        .from(identities)
        .where(eq(identities.id, recipientIdentityId))
        .limit(1);
      recipientPublicKey = recipient?.publicKey || null;
    }

    return c.json({
      success: true,
      message_id: messageId,
      conversation_id: conversationId,
      is_new_conversation: isNewConversation,
      recipient_public_key: recipientPublicKey,
      created_at: now.toISOString(),
    }, isNewConversation ? 201 : 200);

  } catch (error: any) {
    console.error('Error sending message:', error);
    return c.json({ error: 'Failed to send message', details: error.message }, 500);
  }
});

export default messageRoutes;
