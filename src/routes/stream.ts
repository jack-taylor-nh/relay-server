/**
 * Real-time Event Stream (SSE)
 * 
 * GET /v1/stream - Server-Sent Events for real-time updates (identity-based)
 * GET /v1/sse/edge/:edgeId - SSE for bridge apps (edge-based, uses secret key auth)
 * 
 * Architecture:
 * 1. Client connects to /v1/stream with auth token
 * 2. Server subscribes to Redis pub/sub for user's identity
 * 3. When messages arrive, server publishes to Redis
 * 4. Redis forwards to all connected SSE clients
 * 5. Client updates UI instantly, no polling needed
 * 
 * Bridge Architecture:
 * 1. Bridge connects to /v1/sse/edge/:edgeId with Bearer token (X25519 secret key)
 * 2. Server validates edge secret key by deriving public key and comparing
 * 3. Server subscribes to Redis channel for that specific edge
 * 4. Bridge receives messages only for that edge
 */

import { Hono } from 'hono';
import { stream } from 'hono/streaming';
import { authMiddleware } from '../middleware/auth.js';
import { subscribe, unsubscribe } from '../core/redis.js';
import { db, edges } from '../db/index.js';
import { eq } from 'drizzle-orm';
import { fromBase64, toBase64 } from '../core/crypto/index.js';
import nacl from 'tweetnacl';

export const streamRoutes = new Hono();

/**
 * SSE endpoint for bridge apps (edge-based authentication)
 * 
 * Bridge connects with:
 * - URL: /v1/sse/edge/:edgeId
 * - Header: Authorization: Bearer <base64-encoded-x25519-secret-key>
 * 
 * No identity auth required - edge secret key is sufficient
 */
streamRoutes.get('/edge/:edgeId', async (c) => {
  const edgeId = c.req.param('edgeId');
  const authHeader = c.req.header('Authorization');
  
  // Validate auth header
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ 
      code: 'UNAUTHORIZED', 
      message: 'Missing or invalid authorization header' 
    }, 401);
  }
  
  const secretKeyBase64 = authHeader.slice(7);
  
  try {
    // Decode secret key
    const secretKey = fromBase64(secretKeyBase64);
    
    // Derive public key from secret key to verify ownership
    const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
    const derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    
    // Look up edge
    const [edge] = await db
      .select()
      .from(edges)
      .where(eq(edges.id, edgeId))
      .limit(1);
    
    if (!edge) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: 'Edge not found' 
      }, 404);
    }
    
    // Verify the secret key matches the stored public key
    if (edge.x25519PublicKey !== derivedPublicKeyBase64) {
      return c.json({ 
        code: 'UNAUTHORIZED', 
        message: 'Invalid edge secret key' 
      }, 401);
    }
    
    // Check edge is active
    if (edge.status !== 'active') {
      return c.json({ 
        code: 'EDGE_DISABLED', 
        message: 'Edge is not active' 
      }, 403);
    }
    
    console.log(`[SSE Edge] Bridge connected: ${edgeId.slice(0, 8)}... (${edge.type})`);
    
    // Start SSE stream
    return stream(c, async (stream) => {
      // Set SSE headers
      c.header('Content-Type', 'text/event-stream');
      c.header('Cache-Control', 'no-cache');
      c.header('Connection', 'keep-alive');
      c.header('X-Accel-Buffering', 'no'); // Disable nginx buffering
      
      let keepAliveInterval: NodeJS.Timeout | null = null;
      let messageHandler: ((message: string) => void) | null = null;
      
      try {
        // Message handler for edge channel
        messageHandler = (message: string) => {
          try {
            // Parse message from Redis
            const data = JSON.parse(message);
            
            // Send SSE event to bridge
            stream.write(`event: ${data.type}\n`);
            stream.write(`data: ${JSON.stringify(data.payload)}\n\n`);
          } catch (error) {
            console.error('[SSE Edge] Failed to parse message:', error);
          }
        };
        
        // Subscribe to this edge's channel
        const edgeChannel = `edge:${edgeId}:updates`;
        await subscribe(edgeChannel, messageHandler);
        
        console.log(`[SSE Edge] Subscribed to ${edgeChannel}`);
        
        // Send initial connection confirmation
        await stream.write(`event: connected\n`);
        await stream.write(`data: {"timestamp":"${new Date().toISOString()}","edgeId":"${edgeId}"}\n\n`);
        
        // Keepalive ping every 30 seconds
        keepAliveInterval = setInterval(async () => {
          try {
            await stream.write(`: keepalive ${Date.now()}\n\n`);
          } catch (error) {
            // Stream closed, cleanup will happen in finally block
          }
        }, 30000);
        
        // Keep stream open until bridge disconnects
        await new Promise<void>((resolve) => {
          c.req.raw.signal.addEventListener('abort', () => {
            resolve();
          });
        });
        
      } finally {
        // Cleanup on disconnect
        if (keepAliveInterval) {
          clearInterval(keepAliveInterval);
        }
        
        // Unsubscribe from edge channel
        if (messageHandler) {
          const edgeChannel = `edge:${edgeId}:updates`;
          await unsubscribe(edgeChannel, messageHandler);
        }
        
        console.log(`[SSE Edge] Bridge disconnected: ${edgeId.slice(0, 8)}...`);
      }
    });
    
  } catch (error) {
    console.error('[SSE Edge] Error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to authenticate edge' 
    }, 500);
  }
});

// Identity-based stream routes require authentication
streamRoutes.use('*', authMiddleware);

/**
 * SSE endpoint for real-time conversation updates
 * 
 * Events:
 * - conversation_update: New message or conversation state change
 * - ping: Keepalive to prevent connection timeout
 * 
 * Client should:
 * 1. Connect on app start
 * 2. Reconnect on disconnect (exponential backoff)
 * 3. Keep polling as fallback (5min interval)
 */
streamRoutes.get('/', async (c) => {
  const identityId = c.get('fingerprint');
  
  console.log(`[SSE] Client connected: ${identityId.slice(0, 8)}...`);
  
  return stream(c, async (stream) => {
    // Set SSE headers
    c.header('Content-Type', 'text/event-stream');
    c.header('Cache-Control', 'no-cache');
    c.header('Connection', 'keep-alive');
    c.header('X-Accel-Buffering', 'no'); // Disable nginx buffering
    
    let keepAliveInterval: NodeJS.Timeout | null = null;
    let messageHandler: ((message: string) => void) | null = null;
    const subscribedChannels: string[] = [];
    
    try {
      // Message handler for all channels
      messageHandler = (message: string) => {
        try {
          // Parse message from Redis
          const data = JSON.parse(message);
          
          // Send SSE event to client
          stream.write(`event: ${data.type}\n`);
          stream.write(`data: ${JSON.stringify(data.payload)}\n\n`);
        } catch (error) {
          console.error('[SSE] Failed to parse message:', error);
        }
      };
      
      // Subscribe to all owned edges (for both sent and received messages)
      // This avoids identity-level operations and maintains unlinkability
      const { computeQueryKey } = await import('../lib/queryKey.js');
      const { db } = await import('../db/index.js');
      const { edges } = await import('../db/schema.js');
      const { eq } = await import('drizzle-orm');
      
      const ownerQueryKey = computeQueryKey(identityId);
      const userEdges = await db
        .select({ id: edges.id })
        .from(edges)
        .where(eq(edges.ownerQueryKey, ownerQueryKey));
      
      for (const edge of userEdges) {
        const edgeChannel = `edge:${edge.id}:updates`;
        await subscribe(edgeChannel, messageHandler);
        subscribedChannels.push(edgeChannel);
      }
      
      console.log(`[SSE] Subscribed to ${subscribedChannels.length} channels`);
      
      // Send initial connection confirmation
      await stream.write(`event: connected\n`);
      await stream.write(`data: {"timestamp":"${new Date().toISOString()}"}\n\n`);
      
      // Keepalive ping every 30 seconds to prevent timeout
      keepAliveInterval = setInterval(async () => {
        try {
          await stream.write(`: keepalive ${Date.now()}\n\n`);
        } catch (error) {
          // Stream closed, cleanup will happen in finally block
        }
      }, 30000);
      
      // Keep stream open until client disconnects
      await new Promise<void>((resolve) => {
        // Hono's stream will resolve when connection closes
        c.req.raw.signal.addEventListener('abort', () => {
          resolve();
        });
      });
      
    } finally {
      // Cleanup on disconnect
      if (keepAliveInterval) {
        clearInterval(keepAliveInterval);
      }
      
      // Unsubscribe from all channels
      if (messageHandler) {
        for (const ch of subscribedChannels) {
          await unsubscribe(ch, messageHandler);
        }
      }
      
      console.log(`[SSE] Client disconnected: ${identityId.slice(0, 8)}...`);
    }
  });
});
