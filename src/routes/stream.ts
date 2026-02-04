/**
 * Real-time Event Stream (SSE)
 * 
 * GET /v1/stream - Server-Sent Events for real-time updates
 * 
 * Architecture:
 * 1. Client connects to /v1/stream with auth token
 * 2. Server subscribes to Redis pub/sub for user's identity
 * 3. When messages arrive, server publishes to Redis
 * 4. Redis forwards to all connected SSE clients
 * 5. Client updates UI instantly, no polling needed
 */

import { Hono } from 'hono';
import { stream } from 'hono/streaming';
import { authMiddleware } from '../middleware/auth.js';
import { subscribe, unsubscribe } from '../core/redis.js';

export const streamRoutes = new Hono();

// All stream routes require authentication
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
  
  // Redis channel for this identity
  const channel = `identity:${identityId}:updates`;
  
  console.log(`[SSE] Client connected: ${identityId.slice(0, 8)}...`);
  
  return stream(c, async (stream) => {
    // Set SSE headers
    c.header('Content-Type', 'text/event-stream');
    c.header('Cache-Control', 'no-cache');
    c.header('Connection', 'keep-alive');
    c.header('X-Accel-Buffering', 'no'); // Disable nginx buffering
    
    let keepAliveInterval: NodeJS.Timeout | null = null;
    let messageHandler: ((message: string) => void) | null = null;
    
    try {
      // Subscribe to Redis pub/sub for this identity
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
      
      await subscribe(channel, messageHandler);
      
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
      
      if (messageHandler) {
        await unsubscribe(channel, messageHandler);
      }
      
      console.log(`[SSE] Client disconnected: ${identityId.slice(0, 8)}...`);
    }
  });
});
