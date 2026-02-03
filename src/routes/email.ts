/**
 * Email Inbound Routes
 * 
 * Handles incoming emails from the Cloudflare Email Worker
 * 
 * POST /v1/email/inbound - Process inbound email
 * POST /v1/email/send - Send outbound email via Resend
 */

import { Hono } from 'hono';
import { eq, and, not, isNull, or, inArray } from 'drizzle-orm';
import { ulid } from 'ulid';
import { Resend } from 'resend';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { db, edges, conversations, conversationParticipants, messages, bridgeMessages, type EmailBridgeMetadata } from '../db/index.js';
import { authMiddleware } from '../middleware/auth.js';
import { computeQueryKey } from '../lib/queryKey.js';

const { decodeBase64 } = naclUtil;

export const emailRoutes = new Hono();

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

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
    // Clone request to read body (Hono only allows reading body once)
    const bodyText = await c.req.text();
    const body = JSON.parse(bodyText);
    
    const messageToSign = `${body.edgeId}:${body.senderHash}:${body.encryptedPayload}:${body.receivedAt}`;
    const isValid = verifySignature(messageToSign, signature, WORKER_PUBLIC_KEY);
    
    if (!isValid) {
      return c.json({ code: 'INVALID_SIGNATURE', message: 'Worker signature verification failed' }, 401);
    }
    
    // Store parsed body for route handler
    c.set('workerBody', body);
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
 * Process inbound email from worker
 * Phase 5: identityId is now optional - we get it from the edge record
 */
emailRoutes.post('/inbound', workerAuthMiddleware, async (c) => {
  // Get body from middleware if signature was verified, otherwise parse fresh
  type InboundBody = {
    edgeId: string;
    identityId?: string;         // Optional: deprecated, we get it from edge
    senderHash: string;          // Hash for conversation matching
    encryptedPayload: string;    // Entire email encrypted (zero-knowledge)
    encryptedMetadata?: string;  // Encrypted counterparty info for conversation list display
    receivedAt: string;
  };
  
  const body: InboundBody = (c as any).get('workerBody') || await c.req.json<InboundBody>();

  if (!body.edgeId || !body.senderHash || !body.encryptedPayload) {
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

  // Phase 5: Edge ownership verified via ownerQueryKey (no identityId stored)
  // The edge exists and is active, that's all we need to know

  // Look for existing conversation with this sender through this edge
  // Match by: edge_id + senderHash (deterministic per sender)
  const existingConv = await db
    .select({ conversationId: conversationParticipants.conversationId })
    .from(conversationParticipants)
    .innerJoin(conversations, eq(conversations.id, conversationParticipants.conversationId))
    .where(and(
      eq(conversations.edgeId, body.edgeId),
      eq(conversationParticipants.externalId, body.senderHash)  // Match by hash
    ))
    .limit(1);

  let conversationId: string;

  if (existingConv.length > 0) {
    // Use existing conversation
    conversationId = existingConv[0].conversationId;
  } else {
    // Create new conversation
    conversationId = ulid();
    const now = new Date();

    await db.insert(conversations).values({
      id: conversationId,
      origin: 'email',
      edgeId: body.edgeId,
      securityLevel: 'gateway_secured',
      encryptedMetadata: body.encryptedMetadata || null,  // Encrypted counterparty info
      createdAt: now,
      lastActivityAt: now,
    });

    // Add owner as participant using edge ID only - NO identityId for unlinkability
    await db.insert(conversationParticipants).values({
      conversationId,
      // SECURITY: Do NOT store identityId - breaks unlinkability
      edgeId: body.edgeId,
      isOwner: true,
    });

    // Add sender as external participant - store HASH (for matching) not encrypted blob
    await db.insert(conversationParticipants).values({
      conversationId,
      externalId: body.senderHash,  // Deterministic hash
      displayName: null,             // Name is in encrypted payload
    });
  }

  // Create message with encrypted payload (zero-knowledge)
  const messageId = ulid();
  const now = new Date();

  await db.insert(messages).values({
    id: messageId,
    protocolVersion: '1.0',
    conversationId,
    edgeId: body.edgeId,
    origin: 'email',
    securityLevel: 'gateway_secured',
    contentType: 'application/encrypted',
    senderExternalId: body.senderHash,
    encryptedContent: body.encryptedPayload,  // Store encrypted blob
    nonce: null,                               // Nonce is in the encrypted package
    createdAt: now,
  });

  // Store bridge metadata for email (unified table)
  await db.insert(bridgeMessages).values({
    messageId,
    bridgeType: 'email',
    senderExternalId: body.senderHash,
    senderDisplayName: null,  // Name is in encrypted payload
    platformMessageId: null,  // MessageId is encrypted
    metadata: {
      fromAddressHash: body.senderHash,
      // These are encrypted in the payload - only set when known
    } as EmailBridgeMetadata,
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
 * Send outbound email via Resend
 * 
 * SECURITY: Verifies access via edge ownership, not identity
 */
emailRoutes.post('/send', authMiddleware, async (c) => {
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
    .select({ id: edges.id })
    .from(edges)
    .where(eq(edges.ownerQueryKey, ownerQueryKey));

  const userEdgeIds = userEdges.map(e => e.id);

  // Get conversation and verify ownership
  const [conv] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, body.conversationId))
    .limit(1);

  if (!conv) {
    return c.json({ code: 'CONVERSATION_NOT_FOUND', message: 'Conversation not found' }, 404);
  }

  if (!conv.edgeId) {
    return c.json({ code: 'NO_EDGE', message: 'This conversation has no email edge' }, 400);
  }

  // Verify user is a participant (via edge ownership)
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

  if (edge.type !== 'email') {
    return c.json({ code: 'INVALID_EDGE_TYPE', message: 'Edge is not an email edge' }, 400);
  }

  if (edge.status !== 'active') {
    return c.json({ code: 'EDGE_DISABLED', message: 'Edge is disabled' }, 410);
  }

  // Get recipient info (contains encrypted email address)
  // For email conversations, the external participant has no edgeId (they're not Relay users)
  const [participant] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, body.conversationId),
      // External participants don't have edgeId (or it's not in our userEdgeIds)
      or(
        isNull(conversationParticipants.edgeId),
        // If they have edgeId, it must not be one of ours
        ...(userEdgeIds.length > 0 
          ? [not(inArray(conversationParticipants.edgeId, userEdgeIds))]
          : [])
      )
    ))
    .limit(1);

  if (!participant || !participant.externalId) {
    return c.json({ code: 'NO_RECIPIENT', message: 'Cannot find recipient' }, 400);
  }

  // Get original email metadata for reply context from bridge_messages
  const originalMessages = await db
    .select({
      metadata: bridgeMessages.metadata,
    })
    .from(bridgeMessages)
    .innerJoin(messages, eq(messages.id, bridgeMessages.messageId))
    .where(and(
      eq(messages.conversationId, body.conversationId),
      eq(bridgeMessages.bridgeType, 'email')
    ))
    .orderBy(messages.createdAt)
    .limit(1);

  const emailMeta = originalMessages[0]?.metadata as EmailBridgeMetadata | undefined;
  const originalSubject = emailMeta?.subject || '(no subject)';
  const replySubject = originalSubject.startsWith('Re:') ? originalSubject : `Re: ${originalSubject}`;

  // Client must decrypt the first message in conversation to get sender's email
  // The encrypted payload contains: { from, fromName, subject, textBody, ... }
  return c.json({
    // Note: Client must extract recipient email from first message's encrypted payload
    requiresMessageDecryption: true,
    edgeAddress: edge.address,
    replySubject,
    inReplyTo: emailMeta?.emailMessageId,
  });
});

/**
 * Dispatch email after client-side decryption
 * Client decrypts the recipient email and sends it back for actual delivery
 * 
 * SECURITY: Verifies access via edge ownership, not identity
 */
emailRoutes.post('/dispatch', authMiddleware, async (c) => {
  const identityId = c.get('fingerprint');
  
  const body = await c.req.json<{
    conversationId: string;
    recipientEmail: string;  // Decrypted by client
    edgeAddress: string;
    subject: string;
    content: string;
    inReplyTo?: string;
  }>();

  if (!body.conversationId || !body.recipientEmail || !body.content) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Get user's edges via ownerQueryKey
  const ownerQueryKey = computeQueryKey(identityId);
  const userEdges = await db
    .select({ id: edges.id })
    .from(edges)
    .where(eq(edges.ownerQueryKey, ownerQueryKey));

  const userEdgeIds = userEdges.map(e => e.id);

  // Verify user is a participant
  const [conv] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, body.conversationId))
    .limit(1);

  if (!conv) {
    return c.json({ code: 'CONVERSATION_NOT_FOUND', message: 'Conversation not found' }, 404);
  }

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

  // Send via Resend
  try {
    const { data, error } = await resend.emails.send({
      from: `Relay <${body.edgeAddress}>`,
      to: [body.recipientEmail],
      subject: body.subject,
      text: body.content,
      headers: body.inReplyTo ? {
        'In-Reply-To': body.inReplyTo,
      } : undefined,
    });

    if (error) {
      console.error('Resend error:', error);
      return c.json({ code: 'EMAIL_SEND_FAILED', message: error.message }, 500);
    }

    // Store sent message in database
    const messageId = ulid();
    const now = new Date();

    await db.insert(messages).values({
      id: messageId,
      protocolVersion: '1.0',
      conversationId: body.conversationId,
      edgeId: conv.edgeId,
      origin: 'email',
      securityLevel: 'gateway_secured',
      contentType: 'text/plain',
      // Sender identified by edge, not identity
      plaintextContent: body.content,
      createdAt: now,
    });

    // Store email metadata in unified bridge_messages table
    await db.insert(bridgeMessages).values({
      messageId,
      bridgeType: 'email',
      senderExternalId: identityId, // For outbound, this is the sender identity
      senderDisplayName: null,
      platformMessageId: data?.id,  // Resend message ID
      metadata: {
        fromAddressHash: identityId,
        subject: body.subject,
        emailMessageId: data?.id,
      } as EmailBridgeMetadata,
    });

    // Update conversation
    await db
      .update(conversations)
      .set({ lastActivityAt: now })
      .where(eq(conversations.id, body.conversationId));

    return c.json({
      messageId,
      resendId: data?.id,
    }, 201);
  } catch (error) {
    console.error('Email dispatch error:', error);
    return c.json({ code: 'EMAIL_SEND_FAILED', message: 'Failed to send email' }, 500);
  }
});
/**
 * Record sent email message (called after worker sends via MailChannels)
 * Server stores the message in conversation history (encrypted content for zero-knowledge!)
 * 
 * SECURITY: Verifies access via edge ownership, not identity
 */
emailRoutes.post('/record-sent', authMiddleware, async (c) => {
  const identityId = c.get('fingerprint');
  
  const body = await c.req.json<{
    conversationId: string;
    encryptedContent: string;  // Encrypted for identity's key (ephemeralPubkey:nonce:ciphertext)
  }>();

  if (!body.conversationId || !body.encryptedContent) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

  // Get user's edges via ownerQueryKey
  const ownerQueryKey = computeQueryKey(identityId);
  const userEdges = await db
    .select({ id: edges.id })
    .from(edges)
    .where(eq(edges.ownerQueryKey, ownerQueryKey));

  const userEdgeIds = userEdges.map(e => e.id);

  // Verify user is a participant
  const [conv] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, body.conversationId))
    .limit(1);

  if (!conv) {
    return c.json({ code: 'CONVERSATION_NOT_FOUND', message: 'Conversation not found' }, 404);
  }

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

  // Store sent message in database (encrypted!)
  const messageId = ulid();
  const now = new Date();

  await db.insert(messages).values({
    id: messageId,
    protocolVersion: '1.0',
    conversationId: body.conversationId,
    edgeId: conv.edgeId,
    origin: 'email',
    securityLevel: 'gateway_secured',
    contentType: 'application/encrypted',
    // Sender identified by edge, not identity
    encryptedContent: body.encryptedContent,  // Zero-knowledge storage!
    createdAt: now,
  });

  // Update conversation
  await db
    .update(conversations)
    .set({ lastActivityAt: now })
    .where(eq(conversations.id, body.conversationId));

  return c.json({ messageId }, 201);
});