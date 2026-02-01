/**
 * Email Inbound Routes
 * 
 * Handles incoming emails from the Cloudflare Email Worker
 * 
 * POST /v1/email/inbound - Process inbound email
 */

import { Hono } from 'hono';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';
import { db, edges, conversations, conversationParticipants, messages, emailMessages } from '../db/index.js';

export const emailRoutes = new Hono();

// Simple worker auth - shared secret
const WORKER_SECRET = process.env.WORKER_SECRET || 'dev-worker-secret';

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
 * Process inbound email from worker
 */
emailRoutes.post('/inbound', workerAuthMiddleware, async (c) => {
  const body = await c.req.json<{
    edgeId: string;
    identityId: string;
    email: {
      fromAddressHash: string;
      fromName?: string;
      subject: string;
      textBody: string;
      messageId?: string;
      inReplyTo?: string;
      receivedAt: string;
    };
  }>();

  if (!body.edgeId || !body.identityId || !body.email) {
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
  // We match on: edge_id + external_id (sender hash)
  const existingConv = await db
    .select({ conversationId: conversationParticipants.conversationId })
    .from(conversationParticipants)
    .innerJoin(conversations, eq(conversations.id, conversationParticipants.conversationId))
    .where(and(
      eq(conversationParticipants.externalId, body.email.fromAddressHash),
      eq(conversations.edgeId, body.edgeId)
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

    // Add sender as external participant
    await db.insert(conversationParticipants).values({
      conversationId,
      externalId: body.email.fromAddressHash,
      displayName: body.email.fromName,
    });
  }

  // Create message
  const messageId = ulid();
  const now = new Date();

  await db.insert(messages).values({
    id: messageId,
    protocolVersion: '1.0',
    conversationId,
    edgeId: body.edgeId,
    origin: 'email',
    securityLevel: 'gateway_secured',
    contentType: 'text/plain',
    senderExternalId: body.email.fromAddressHash,
    plaintextContent: body.email.textBody,
    createdAt: now,
  });

  // Store email-specific metadata
  await db.insert(emailMessages).values({
    messageId,
    fromAddressHash: body.email.fromAddressHash,
    subject: body.email.subject,
    emailMessageId: body.email.messageId,
    inReplyTo: body.email.inReplyTo,
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
