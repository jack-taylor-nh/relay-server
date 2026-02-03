/**
 * Discord Inbound Routes
 * 
 * Handles incoming Discord messages from the Discord Worker
 * 
 * POST /v1/discord/inbound - Process inbound Discord DM
 * POST /v1/discord/send - Send outbound Discord DM via worker
 */

import { Hono } from 'hono';
import { eq, and, inArray, sql } from 'drizzle-orm';
import { ulid } from 'ulid';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { db, edges, conversations, conversationParticipants, messages, bridgeMessages, type DiscordBridgeMetadata } from '../db/index.js';
import { authMiddleware } from '../middleware/auth.js';
import { computeQueryKey } from '../lib/queryKey.js';

const { decodeBase64, encodeBase64 } = naclUtil;

export const discordRoutes = new Hono();

// Worker auth
const WORKER_SECRET = process.env.DISCORD_WORKER_SECRET || process.env.WORKER_SECRET || 'dev-worker-secret';
const DISCORD_WORKER_URL = process.env.DISCORD_WORKER_URL || 'http://localhost:3001';
const DISCORD_BRIDGE_PUBLIC_KEY = process.env.DISCORD_BRIDGE_PUBLIC_KEY; // X25519 public key for encrypting to bridge

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
  
  await next();
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
 * Process inbound Discord DM from worker
 * 
 * Discord user sends: /relay &handle message
 * Worker encrypts and forwards here
 * 
 * PRIVACY: We store only hashed identifiers for matching.
 * The actual Discord user ID is encrypted and only the worker can decrypt it.
 */
discordRoutes.post('/inbound', workerAuthMiddleware, async (c) => {
  type InboundBody = {
    edgeId: string;              // Target Relay edge (the handle being messaged)
    senderHash: string;          // Hash of Discord user ID for conversation matching
    encryptedRecipientId: string; // Encrypted Discord user ID (only worker can decrypt for replies)
    encryptedPayload: string;    // Discord message encrypted for Relay user (zero-knowledge)
    encryptedMetadata?: string;  // Encrypted counterparty info for conversation list display
    discordMessageId?: string;   // Discord message ID for reply threading
    receivedAt: string;
  };
  
  const body = await c.req.json<InboundBody>();

  if (!body.edgeId || !body.senderHash || !body.encryptedPayload || !body.encryptedRecipientId) {
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
      origin: 'discord',
      edgeId: body.edgeId,
      securityLevel: 'gateway_secured',
      encryptedMetadata: body.encryptedMetadata || null,  // Encrypted counterparty info
      createdAt: now,
      lastActivityAt: now,
    });

    // Add owner as participant
    await db.insert(conversationParticipants).values({
      conversationId,
      edgeId: body.edgeId,
      isOwner: true,
    });

    // Add sender as external participant (hash only, no display name stored)
    await db.insert(conversationParticipants).values({
      conversationId,
      externalId: body.senderHash,
      displayName: null,  // Display name is in encrypted payload
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
    origin: 'discord',
    securityLevel: 'gateway_secured',
    contentType: 'application/encrypted',
    senderExternalId: body.senderHash,
    encryptedContent: body.encryptedPayload,
    nonce: null,
    createdAt: now,
  });

  // Store bridge-specific metadata for reply routing (unified table)
  // PRIVACY: Only store hash for matching, encrypted ID for reply routing
  await db.insert(bridgeMessages).values({
    messageId,
    bridgeType: 'discord',
    senderExternalId: body.senderHash,  // Hash for conversation matching
    senderDisplayName: null,            // Display name is in encrypted payload
    platformMessageId: body.discordMessageId || null,  // For reply threading
    metadata: {
      // Store encrypted Discord ID - only worker can decrypt for replies
      encryptedDiscordId: body.encryptedRecipientId,
      discordMessageId: body.discordMessageId,  // For reply threading
    } as DiscordBridgeMetadata,
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

  return c.json({
    conversationId,
    messageId,
    isNewConversation: existingConv.length === 0,
  }, 201);
});

/**
 * Send outbound Discord DM via worker
 * 
 * Relay user replies to a Discord conversation
 * We look up the Discord user ID from the conversation and forward to worker
 */
discordRoutes.post('/send', authMiddleware, async (c) => {
  const identityId = c.get('fingerprint');
  
  const body = await c.req.json<{
    conversationId: string;
    content: string;
  }>();

  if (!body.conversationId || !body.content) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Get user's edges via ownerQueryKey
  const ownerQueryKey = computeQueryKey(identityId);
  const userEdges = await db
    .select({ id: edges.id, address: edges.address })
    .from(edges)
    .where(eq(edges.ownerQueryKey, ownerQueryKey));

  const userEdgeIds = userEdges.map(e => e.id);

  // Get conversation
  const [conv] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, body.conversationId))
    .limit(1);

  if (!conv) {
    return c.json({ code: 'CONVERSATION_NOT_FOUND', message: 'Conversation not found' }, 404);
  }

  if (!conv.edgeId) {
    return c.json({ code: 'NO_EDGE', message: 'This conversation has no edge' }, 400);
  }

  if (conv.origin !== 'discord') {
    return c.json({ code: 'INVALID_ORIGIN', message: 'This is not a Discord conversation' }, 400);
  }

  // Verify user is a participant
  const [participation] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, body.conversationId),
      inArray(conversationParticipants.edgeId, userEdgeIds.length > 0 ? userEdgeIds : ['__none__'])
    ))
    .limit(1);

  if (!participation) {
    return c.json({ code: 'FORBIDDEN', message: 'You are not a participant' }, 403);
  }

  // Get edge info
  const [edge] = await db
    .select()
    .from(edges)
    .where(eq(edges.id, conv.edgeId))
    .limit(1);

  if (!edge) {
    return c.json({ code: 'EDGE_NOT_FOUND', message: 'Edge not found' }, 404);
  }

  if (edge.status !== 'active') {
    return c.json({ code: 'EDGE_DISABLED', message: 'Edge is disabled' }, 410);
  }

  // Look up the encrypted Discord ID and most recent message ID from the conversation's bridge messages
  // The actual Discord ID is encrypted - only the worker can decrypt it
  // We get the MOST RECENT message to reply to for threading
  const [bridgeMsg] = await db
    .select({ 
      messageId: bridgeMessages.messageId,
      metadata: bridgeMessages.metadata,
      platformMessageId: bridgeMessages.platformMessageId,
    })
    .from(bridgeMessages)
    .innerJoin(messages, eq(messages.id, bridgeMessages.messageId))
    .where(and(
      eq(messages.conversationId, body.conversationId),
      eq(bridgeMessages.bridgeType, 'discord')
    ))
    .orderBy(sql`${messages.createdAt} DESC`)  // Get most recent for reply threading
    .limit(1);

  if (!bridgeMsg || !bridgeMsg.metadata) {
    return c.json({ code: 'NO_RECIPIENT', message: 'Could not find Discord recipient for this conversation' }, 400);
  }

  const discordMetadata = bridgeMsg.metadata as DiscordBridgeMetadata;
  if (!discordMetadata.encryptedDiscordId) {
    return c.json({ code: 'NO_RECIPIENT', message: 'Could not find encrypted Discord ID' }, 400);
  }

  // Get the conversation message ID (the bot's message we'll edit to append replies)
  const conversationMessageId = discordMetadata.conversationMessageId;

  // Forward to Discord worker with the ENCRYPTED Discord ID
  // Worker will decrypt it using its private key to get the actual Discord user ID
  try {
    const response = await fetch(`${DISCORD_WORKER_URL}/send`, {
      method: 'POST',
      headers: {
        'Authorization': `Worker ${WORKER_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        conversationId: body.conversationId,
        content: body.content,
        encryptedRecipientId: discordMetadata.encryptedDiscordId,  // Worker decrypts this
        edgeAddress: edge.address,
        conversationMessageId,  // For editing the conversation message
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('Discord worker error:', error);
      return c.json({ code: 'WORKER_ERROR', message: 'Failed to send Discord message' }, 500);
    }

    const result = await response.json() as { 
      success: boolean; 
      messageId?: string; 
      conversationMessageId?: string;
      error?: string;
    };

    if (!result.success) {
      return c.json({ code: 'SEND_FAILED', message: result.error || 'Failed to send' }, 500);
    }

    // If worker returned a new conversation message ID, store it
    if (result.conversationMessageId && result.conversationMessageId !== conversationMessageId) {
      const updatedMetadata: DiscordBridgeMetadata = {
        ...discordMetadata,
        conversationMessageId: result.conversationMessageId,
      };
      await db
        .update(bridgeMessages)
        .set({ metadata: updatedMetadata })
        .where(eq(bridgeMessages.messageId, bridgeMsg.messageId));
    }

    // Store outbound message
    const messageId = ulid();
    const now = new Date();

    await db.insert(messages).values({
      id: messageId,
      protocolVersion: '1.0',
      conversationId: body.conversationId,
      edgeId: conv.edgeId,
      origin: 'discord',
      securityLevel: 'gateway_secured',
      contentType: 'text/plain',
      plaintextContent: body.content,  // Outbound messages are plaintext
      nonce: null,
      createdAt: now,
    });

    // Update conversation activity
    await db
      .update(conversations)
      .set({ lastActivityAt: now })
      .where(eq(conversations.id, body.conversationId));

    return c.json({
      messageId,
      discordMessageId: result.messageId,
      conversationMessageId: result.conversationMessageId,
    }, 201);

  } catch (error) {
    console.error('Discord send error:', error);
    return c.json({ code: 'WORKER_UNREACHABLE', message: 'Could not reach Discord worker' }, 503);
  }
});

/**
 * Update the conversation message ID for a Discord conversation
 * Called by the worker after creating the bot's conversation message
 */
discordRoutes.post('/conversation-message', workerAuthMiddleware, async (c) => {
  const body = await c.req.json<{
    conversationId: string;
    conversationMessageId: string;
  }>();

  if (!body.conversationId || !body.conversationMessageId) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Find the bridge message for this conversation and update its metadata
  const [bridgeMsg] = await db
    .select({ 
      messageId: bridgeMessages.messageId,
      metadata: bridgeMessages.metadata,
    })
    .from(bridgeMessages)
    .innerJoin(messages, eq(messages.id, bridgeMessages.messageId))
    .where(and(
      eq(messages.conversationId, body.conversationId),
      eq(bridgeMessages.bridgeType, 'discord')
    ))
    .limit(1);

  if (!bridgeMsg) {
    return c.json({ code: 'NOT_FOUND', message: 'No bridge message found for conversation' }, 404);
  }

  // Update metadata with conversation message ID
  const existingMetadata = (bridgeMsg.metadata || {}) as DiscordBridgeMetadata;
  const updatedMetadata: DiscordBridgeMetadata = {
    ...existingMetadata,
    conversationMessageId: body.conversationMessageId,
  };

  await db
    .update(bridgeMessages)
    .set({ metadata: updatedMetadata })
    .where(eq(bridgeMessages.messageId, bridgeMsg.messageId));

  console.log(`Updated conversation message ID for ${body.conversationId}: ${body.conversationMessageId}`);

  return c.json({ success: true });
});

/**
 * Look up existing conversation for a Discord user + Relay edge
 * Used by worker to check if a conversation message already exists
 */
discordRoutes.post('/lookup-conversation', workerAuthMiddleware, async (c) => {
  const body = await c.req.json<{
    senderHash: string;
    edgeId: string;
  }>();

  if (!body.senderHash || !body.edgeId) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Find conversation by edge + external participant hash
  const existingConv = await db
    .select({ 
      conversationId: conversationParticipants.conversationId,
    })
    .from(conversationParticipants)
    .innerJoin(conversations, eq(conversations.id, conversationParticipants.conversationId))
    .where(and(
      eq(conversations.edgeId, body.edgeId),
      eq(conversationParticipants.externalId, body.senderHash)
    ))
    .limit(1);

  if (existingConv.length === 0) {
    return c.json({ code: 'NOT_FOUND', message: 'No existing conversation' }, 404);
  }

  const conversationId = existingConv[0].conversationId;

  // Get the conversation message ID from bridge messages metadata
  const [bridgeMsg] = await db
    .select({ 
      metadata: bridgeMessages.metadata,
    })
    .from(bridgeMessages)
    .innerJoin(messages, eq(messages.id, bridgeMessages.messageId))
    .where(and(
      eq(messages.conversationId, conversationId),
      eq(bridgeMessages.bridgeType, 'discord')
    ))
    .orderBy(sql`${messages.createdAt} DESC`)
    .limit(1);

  const discordMetadata = bridgeMsg?.metadata as DiscordBridgeMetadata | undefined;

  return c.json({
    conversationId,
    conversationMessageId: discordMetadata?.conversationMessageId,
  });
});

/**
 * Get Discord bridge public key
 * Used by clients to encrypt recipient IDs
 */
discordRoutes.get('/bridge-key', async (c) => {
  // Look up discord bridge edge
  const [bridge] = await db
    .select({ x25519PublicKey: edges.x25519PublicKey })
    .from(edges)
    .where(and(
      eq(edges.type, 'bridge'),
      eq(edges.address, 'discord'),
      eq(edges.status, 'active')
    ))
    .limit(1);

  if (!bridge || !bridge.x25519PublicKey) {
    return c.json({ code: 'BRIDGE_NOT_FOUND', message: 'Discord bridge not registered' }, 404);
  }

  return c.json({
    publicKey: bridge.x25519PublicKey,
  });
});
