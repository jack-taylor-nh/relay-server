/**
 * Message Routes
 * 
 * POST /v1/messages - Send a message (unified endpoint for all conversation types)
 */

import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db } from '../db/index.js';
import { identities, edges, conversations, conversationParticipants, messages, type SecurityLevel, type EdgeType } from '../db/schema.js';
import { authMiddleware } from '../middleware/auth.js';
import { computeQueryKey } from '../lib/queryKey.js';
import { invalidateCache, publish } from '../core/redis.js';

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
    // 1. Verify sender owns the edge via ownerQueryKey (not identity_id)
    const senderQueryKey = computeQueryKey(senderIdentityId);
    
    const [senderEdge] = await db
      .select()
      .from(edges)
      .where(and(
        eq(edges.id, body.edge_id),
        eq(edges.ownerQueryKey, senderQueryKey)
      ))
      .limit(1);

    if (!senderEdge) {
      return c.json({ error: 'Edge not found or not owned by sender' }, 403);
    }

    let conversationId = body.conversation_id;
    let recipientEdgeId: string | null = null;
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

      // SECURITY: Verify participation via edge ID only (no identity fallback)
      const participation = await db
        .select()
        .from(conversationParticipants)
        .where(and(
          eq(conversationParticipants.conversationId, conversationId),
          eq(conversationParticipants.edgeId, body.edge_id)
        ))
        .limit(1)
        .then(r => r[0]);

      if (!participation) {
        return c.json({ error: 'Not a participant in this conversation' }, 403);
      }
    } else if (body.recipient_handle) {
      // New native conversation - resolve recipient and create conversation
      if (body.origin !== 'native') {
        return c.json({ error: 'recipient_handle is only valid for native origin' }, 400);
      }

      // Resolve recipient edge by address (handle = native edge address)
      // SECURITY: We only need the edge ID, not the identity
      const [recipientEdge] = await db
        .select({
          id: edges.id,
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
        recipientEdgeId = recipientEdge.id;
      } else {
        // No native edge with that address found
        return c.json({ error: 'Recipient handle not found' }, 404);
      }

      // Check for existing conversation between these two edges
      let existingConversationId: string | undefined = undefined;
      
      // Edge-based lookup only - no identity fallback for privacy
      if (recipientEdgeId) {
        const senderEdgeConversations = await db
          .select({ conversationId: conversationParticipants.conversationId })
          .from(conversationParticipants)
          .where(eq(conversationParticipants.edgeId, body.edge_id));

        for (const conv of senderEdgeConversations) {
          const [recipientParticipation] = await db
            .select()
            .from(conversationParticipants)
            .where(and(
              eq(conversationParticipants.conversationId, conv.conversationId),
              eq(conversationParticipants.edgeId, recipientEdgeId)
            ))
            .limit(1);

          if (recipientParticipation) {
            existingConversationId = conv.conversationId;
            break;
          }
        }
      }
      
      // SECURITY: Removed identity-based fallback - only edge-based lookups
      // This preserves unlinkability: server cannot correlate edges to identities
      
      conversationId = existingConversationId;

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
          // Note: No channelLabel - counterparty handle is resolved from participants table
          lastActivityAt: now,
          createdAt: now,
        });

        // Add both participants with edge IDs only - NO identityId for unlinkability
        await db.insert(conversationParticipants).values([
          {
            conversationId,
            // SECURITY: Do NOT store identityId - breaks unlinkability
            edgeId: body.edge_id,
            isOwner: true,
            joinedAt: now,
          },
          {
            conversationId,
            // SECURITY: Do NOT store identityId - breaks unlinkability
            edgeId: recipientEdgeId ?? undefined,
            isOwner: false,
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
      // Sender is identified by edgeId, not identityId
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
    
    // 5. Invalidate conversation list cache and publish real-time updates
    await invalidateCache(`conversations:*`);
    
    // Notify the sender via their edge channel (consistent with inbound)
    await publish(`edge:${body.edge_id}:updates`, {
      type: 'conversation_update',
      payload: {
        conversationId: conversationId!,
        messageId,
        timestamp: now.toISOString(),
      },
    });
    
    // Note: Using edge-based channels avoids any identity-level operations
    // and maintains consistency with inbound message notifications

    // 6. For gateway_secured messages, forward to appropriate worker
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

    // 6. Get recipient's X25519 public key if this was a new conversation (client needs it for encryption)
    // SECURITY: We get this from the edge, not by querying identity
    let recipientX25519Key: string | null = null;
    if (recipientEdgeId) {
      const [recipEdge] = await db
        .select({ x25519PublicKey: edges.x25519PublicKey })
        .from(edges)
        .where(eq(edges.id, recipientEdgeId))
        .limit(1);
      recipientX25519Key = recipEdge?.x25519PublicKey || null;
    }

    return c.json({
      success: true,
      message_id: messageId,
      conversation_id: conversationId,
      is_new_conversation: isNewConversation,
      recipient_x25519_key: recipientX25519Key,  // X25519 key for encryption
      created_at: now.toISOString(),
    }, isNewConversation ? 201 : 200);

  } catch (error: any) {
    console.error('Error sending message:', error);
    return c.json({ error: 'Failed to send message', details: error.message }, 500);
  }
});

export default messageRoutes;
