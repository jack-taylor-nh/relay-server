/**
 * Message Routes
 * 
 * POST /v1/messages - Send a message (unified endpoint for all conversation types)
 */

import { Hono } from 'hono';
import { eq, and, inArray } from 'drizzle-orm';
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
 *   // Either conversation_id (existing), recipient_handle (new native), or recipient_edge_id (new non-native)
 *   conversation_id?: string,
 *   recipient_handle?: string,  // For new native conversations
 *   recipient_edge_id?: string, // For new non-native conversations (webhook, discord, etc.)
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
    recipient_edge_id?: string;
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

  // Must have either conversation_id, recipient_handle, or recipient_edge_id
  if (!body.conversation_id && !body.recipient_handle && !body.recipient_edge_id) {
    return c.json({ 
      error: 'Must provide either conversation_id (existing), recipient_handle (new native), or recipient_edge_id (new non-native)' 
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
    let conversationOrigin: string | null = null;

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
      
      conversationOrigin = conversation.origin;

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
    } else if (body.recipient_edge_id) {
      // New non-native conversation - use recipient_edge_id directly
      recipientEdgeId = body.recipient_edge_id;

      // Verify recipient edge exists
      const [recipientEdge] = await db
        .select({ id: edges.id })
        .from(edges)
        .where(and(
          eq(edges.id, body.recipient_edge_id),
          eq(edges.status, 'active')
        ))
        .limit(1);

      if (!recipientEdge) {
        return c.json({ error: 'Recipient edge not found' }, 404);
      }

      // Check for existing conversation between these two edges
      let existingConversationId: string | undefined = undefined;
      
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
      
      conversationId = existingConversationId;

      // Create new conversation if none exists
      if (!conversationId) {
        conversationId = ulid();
        const now = new Date();
        isNewConversation = true;
        conversationOrigin = body.origin;

        await db.insert(conversations).values({
          id: conversationId,
          edgeId: body.edge_id,
          origin: body.origin as EdgeType,
          securityLevel: body.security_level,
          lastActivityAt: now,
          createdAt: now,
        });

        // Add both participants with edge IDs only
        await db.insert(conversationParticipants).values([
          {
            conversationId,
            edgeId: body.edge_id,
            isOwner: true,
            joinedAt: now,
          },
          {
            conversationId,
            edgeId: recipientEdgeId,
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
    
    // 🎯 CRITICAL: Notify the recipient via their edge channel
    // This is what allows bridges (desktop app, etc.) to receive messages
    if (recipientEdgeId) {
      console.log(`[Messages] Publishing to recipient edge channel: edge:${recipientEdgeId}:updates`);
      await publish(`edge:${recipientEdgeId}:updates`, {
        type: 'edge.message',
        payload: {
          conversationId: conversationId!,
          messageId,
          timestamp: now.toISOString(),
        },
      });
    }
    
    // For contact_link conversations, also publish to conversation channel for visitor
    if (conversationOrigin === 'contact_link') {
      await publish(`conversation:${conversationId}`, {
        type: 'new_message',
        conversationId: conversationId!,
        messageId,
      });
    }
    
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

/**
 * GET /v1/messages/:messageId - Fetch a specific message by ID
 * 
 * Supports edge-based authentication (X25519 Bearer token) for bridge apps
 * or JWT authentication for extension clients.
 * 
 * Returns the full message including encrypted content.
 */
messageRoutes.get('/:messageId', async (c) => {
  const messageId = c.req.param('messageId');
  const authHeader = c.req.header('Authorization');
  
  console.log(`[Messages GET] Request for message: ${messageId}`);
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('[Messages GET] Missing or invalid auth header');
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing or invalid authorization header' }, 401);
  }
  
  const token = authHeader.slice(7);
  console.log(`[Messages GET] Token length: ${token.length}, starts with: ${token.substring(0, 20)}...`);
  
  let authenticatedEdgeId: string | null = null;
  let authenticatedIdentityId: string | null = null;
  
  // Try X25519 edge authentication first (for bridge apps)
  try {
    const { fromBase64, toBase64 } = await import('../core/crypto/index.js');
    const nacl = (await import('tweetnacl')).default;
    
    const secretKey = fromBase64(token);
    const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
    const derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    
    console.log(`[Messages GET] Derived public key: ${derivedPublicKeyBase64.substring(0, 20)}...`);
    
    // Look up edge by X25519 public key
    const [edge] = await db
      .select({ id: edges.id, status: edges.status })
      .from(edges)
      .where(eq(edges.x25519PublicKey, derivedPublicKeyBase64))
      .limit(1);
      
    if (edge && edge.status === 'active') {
      authenticatedEdgeId = edge.id;
      console.log(`[Messages GET] Edge authenticated: ${authenticatedEdgeId.slice(0, 8)}...`);
    } else {
      console.log(`[Messages GET] No matching edge found for public key`);
    }
  } catch (edgeAuthError) {
    console.log(`[Messages GET] Edge auth error:`, edgeAuthError);
  }
  
  // If edge auth failed, try JWT authentication
  if (!authenticatedEdgeId) {
    console.log('[Messages GET] Trying JWT authentication...');
    try {
      const { verifySessionToken } = await import('../lib/jwt.js');
      const payload = await verifySessionToken(token);
      
      if (payload && payload.fingerprint && payload.exp && payload.exp >= Math.floor(Date.now() / 1000)) {
        authenticatedIdentityId = payload.fingerprint;
        console.log(`[Messages GET] JWT authenticated: ${authenticatedIdentityId.slice(0, 8)}...`);
      }
    } catch (jwtError) {
      console.log(`[Messages GET] JWT auth error:`, jwtError);
      return c.json({ code: 'UNAUTHORIZED', message: 'Invalid token' }, 401);
    }
  }
  
  if (!authenticatedEdgeId && !authenticatedIdentityId) {
    console.log('[Messages GET] Authentication failed for both edge and JWT');
    return c.json({ code: 'UNAUTHORIZED', message: 'Authentication failed' }, 401);
  }
  
  console.log(`[Messages GET] Authentication successful, fetching message...`);
  
  // Fetch the message
  const [message] = await db
    .select()
    .from(messages)
    .where(eq(messages.id, messageId))
    .limit(1);
    
  if (!message) {
    console.log(`[Messages GET] Message not found: ${messageId}`);
    return c.json({ code: 'MESSAGE_NOT_FOUND', message: 'Message not found' }, 404);
  }
  
  console.log(`[Messages GET] Message found, checking access...`);
  
  // Verify access: Check if authenticated edge/identity is a participant
  let hasAccess = false;
  
  if (authenticatedEdgeId) {
    // For edge auth: Check if edge is a participant in the conversation
    const [participant] = await db
      .select()
      .from(conversationParticipants)
      .where(and(
        eq(conversationParticipants.conversationId, message.conversationId),
        eq(conversationParticipants.edgeId, authenticatedEdgeId)
      ))
      .limit(1);
      
    hasAccess = !!participant;
    console.log(`[Messages GET] Edge access check: ${hasAccess}, participant found: ${!!participant}`);
  } else if (authenticatedIdentityId) {
    // For JWT auth: Check if any of user's edges is a participant
    const ownerQueryKey = computeQueryKey(authenticatedIdentityId);
    const userEdges = await db
      .select({ id: edges.id })
      .from(edges)
      .where(eq(edges.ownerQueryKey, ownerQueryKey));
      
    const userEdgeIds = userEdges.map(e => e.id);
    console.log(`[Messages GET] JWT user has ${userEdgeIds.length} edges`);
    
    if (userEdgeIds.length > 0) {
      const [participant] = await db
        .select()
        .from(conversationParticipants)
        .where(and(
          eq(conversationParticipants.conversationId, message.conversationId),
          inArray(conversationParticipants.edgeId, userEdgeIds)
        ))
        .limit(1);
        
      hasAccess = !!participant;
      console.log(`[Messages GET] JWT access check: ${hasAccess}`);
    }
  }
  
  if (!hasAccess) {
    console.log(`[Messages GET] Access denied for message ${messageId}`);
    return c.json({ code: 'FORBIDDEN', message: 'Access denied to this message' }, 403);
  }
  
  console.log(`[Messages GET] Access granted, returning message`);
  
  // Return the full message
  return c.json({
    id: message.id,
    conversationId: message.conversationId,
    edgeId: message.edgeId,
    senderEdgeId: message.edgeId,  // Derived: Sender identified by edge
    senderExternalId: message.senderExternalId,
    ciphertext: message.ciphertext,
    ephemeralPubkey: message.ephemeralPubkey,
    nonce: message.nonce,
    ratchetPn: message.ratchetPn,
    ratchetN: message.ratchetN,
    encryptedContent: message.encryptedContent,
    plaintextContent: message.plaintextContent,
    contentType: message.contentType,
    origin: message.origin,
    securityLevel: message.securityLevel,
    createdAt: message.createdAt.toISOString(),
  });
});

export default messageRoutes;
