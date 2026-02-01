/**
 * Email Inbound Routes
 * 
 * Handles incoming emails from the Cloudflare Email Worker
 * 
 * POST /v1/email/inbound - Process inbound email
 * POST /v1/email/send - Send outbound email via Resend
 */

import { Hono } from 'hono';
import { eq, and, not, isNull, or } from 'drizzle-orm';
import { ulid } from 'ulid';
import { Resend } from 'resend';
import { db, edges, conversations, conversationParticipants, messages, emailMessages } from '../db/index.js';
import { authMiddleware } from '../middleware/auth.js';

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
    const nacl = require('tweetnacl');
    const { decodeBase64 } = require('tweetnacl-util');
    
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
 */
emailRoutes.post('/inbound', workerAuthMiddleware, async (c) => {
  // Get body from middleware if signature was verified, otherwise parse fresh
  type InboundBody = {
    edgeId: string;
    identityId: string;
    senderHash: string;          // Hash for conversation matching
    encryptedPayload: string;    // Entire email encrypted (zero-knowledge)
    receivedAt: string;
  };
  
  const body: InboundBody = (c.get('workerBody') as InboundBody | undefined) || await c.req.json<InboundBody>();

  if (!body.edgeId || !body.identityId || !body.senderHash || !body.encryptedPayload) {
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

  if (edge.identityId !== body.identityId) {
    return c.json({ code: 'EDGE_MISMATCH', message: 'Edge does not belong to identity' }, 400);
  }

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
      channelLabel: 'Relayed via Email',
      createdAt: now,
      lastActivityAt: now,
    });

    // Add owner as participant
    await db.insert(conversationParticipants).values({
      conversationId,
      identityId: body.identityId,
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

  // Store email-specific metadata (minimal, for threading)
  await db.insert(emailMessages).values({
    messageId,
    fromAddressHash: body.senderHash,
    subject: null,        // Subject is encrypted
    emailMessageId: null, // MessageId is encrypted
    inReplyTo: null,      // InReplyTo is encrypted
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

  // Verify user is a participant
  const [participation] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, body.conversationId),
      eq(conversationParticipants.identityId, identityId)
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
  // For email conversations, the external participant has NULL identityId
  const [participant] = await db
    .select()
    .from(conversationParticipants)
    .where(and(
      eq(conversationParticipants.conversationId, body.conversationId),
      or(
        not(eq(conversationParticipants.identityId, identityId)),
        isNull(conversationParticipants.identityId)
      )
    ))
    .limit(1);

  if (!participant || !participant.externalId) {
    return c.json({ code: 'NO_RECIPIENT', message: 'Cannot find recipient' }, 400);
  }

  // Get original email metadata for reply context
  const originalMessages = await db
    .select({
      subject: emailMessages.subject,
      emailMessageId: emailMessages.emailMessageId,
    })
    .from(emailMessages)
    .innerJoin(messages, eq(messages.id, emailMessages.messageId))
    .where(eq(messages.conversationId, body.conversationId))
    .orderBy(messages.createdAt)
    .limit(1);

  const originalSubject = originalMessages[0]?.subject || '(no subject)';
  const replySubject = originalSubject.startsWith('Re:') ? originalSubject : `Re: ${originalSubject}`;

  // Return encrypted email to client for decryption
  return c.json({
    encryptedRecipient: participant.externalId,
    edgeAddress: edge.address,
    replySubject,
    inReplyTo: originalMessages[0]?.emailMessageId,
  });
});

/**
 * Dispatch email after client-side decryption
 * Client decrypts the recipient email and sends it back for actual delivery
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
      eq(conversationParticipants.identityId, identityId)
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
      senderIdentityId: identityId,
      plaintextContent: body.content,
      createdAt: now,
    });

    // Store email metadata
    await db.insert(emailMessages).values({
      messageId,
      fromAddressHash: identityId,
      subject: body.subject,
      emailMessageId: data?.id,
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
 * Server stores the message in conversation history (plaintext for now)
 */
emailRoutes.post('/record-sent', authMiddleware, async (c) => {
  const identityId = c.get('fingerprint');
  
  const body = await c.req.json<{
    conversationId: string;
    content: string;
  }>();

  if (!body.conversationId || !body.content) {
    return c.json({ code: 'VALIDATION_ERROR', message: 'Missing required fields' }, 400);
  }

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
      eq(conversationParticipants.identityId, identityId)
    ))
    .limit(1);

  if (!participation) {
    return c.json({ code: 'FORBIDDEN', message: 'You are not a participant' }, 403);
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
    senderIdentityId: identityId,
    plaintextContent: body.content,
    createdAt: now,
  });

  // Update conversation
  await db
    .update(conversations)
    .set({ lastActivityAt: now })
    .where(eq(conversations.id, body.conversationId));

  return c.json({ messageId }, 201);
});