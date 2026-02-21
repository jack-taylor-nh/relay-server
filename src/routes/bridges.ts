/**
 * Bridge Routes
 * 
 * Endpoints for bridge management and monitoring
 * 
 * POST /v1/bridge/heartbeat - Bridge heartbeat (status update)
 * GET /v1/bridge/:edgeId/status - Get current bridge status
 * GET /v1/bridge/:edgeId/history - Get bridge status history
 * GET /v1/bridge/:edgeId/uptime - Get bridge uptime statistics
 */

import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db, edges, type BridgeStatus } from '../db/index.js';
import { 
  logBridgeStatus, 
  getCurrentBridgeStatus, 
  getBridgeStatusHistory,
  getBridgeUptimeStats,
  type BridgeStatusMetadata 
} from '../lib/bridge-status.js';
import { fromBase64, toBase64 } from '../core/crypto/index.js';
import nacl from 'tweetnacl';

export const bridgeRoutes = new Hono();

/**
 * POST /v1/bridge/heartbeat - Bridge heartbeat (status update)
 * 
 * Bridges should send regular heartbeat updates to track connection status.
 * This endpoint logs the status change and returns server time for clock sync.
 * 
 * Authentication: X25519 secret key in Authorization header (same as SSE)
 * Format: Authorization: Bearer <base64-encoded-x25519-secret-key>
 */
bridgeRoutes.post('/heartbeat', async (c) => {
  try {
    // Verify authentication
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ 
        code: 'AUTH_REQUIRED', 
        message: 'Authorization header required' 
      }, 401);
    }

    const secretKeyBase64 = authHeader.substring(7);
    
    // Decode secret key and derive public key
    let derivedPublicKeyBase64: string;
    try {
      const secretKey = fromBase64(secretKeyBase64);
      const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
      derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    } catch (error) {
      return c.json({ 
        code: 'INVALID_KEY', 
        message: 'Invalid secret key format' 
      }, 401);
    }

    // Find edge by matching public key
    const bridgeEdges = await db
      .select()
      .from(edges)
      .where(eq(edges.x25519PublicKey, derivedPublicKeyBase64))
      .limit(1);

    if (bridgeEdges.length === 0) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: 'Bridge edge not found or invalid credentials' 
      }, 404);
    }

    const bridgeEdge = bridgeEdges[0];

    if (bridgeEdge.status !== 'active') {
      return c.json({ 
        code: 'EDGE_INACTIVE', 
        message: 'Bridge edge is not active' 
      }, 403);
    }

    // Parse request body
    const body = await c.req.json<{
      status: BridgeStatus;
      previousStatus?: BridgeStatus;
      connectionDurationMs?: number;
      reconnectAttempt?: number;
      errorMessage?: string;
      metadata?: BridgeStatusMetadata;
    }>();

    // Validate status
    const validStatuses: BridgeStatus[] = ['disconnected', 'connecting', 'connected', 'reconnecting', 'failed'];
    if (!body.status || !validStatuses.includes(body.status)) {
      return c.json({ 
        code: 'INVALID_STATUS', 
        message: `Status must be one of: ${validStatuses.join(', ')}` 
      }, 400);
    }

    // Log the status change
    const eventId = await logBridgeStatus({
      edgeId: bridgeEdge.id,
      status: body.status,
      previousStatus: body.previousStatus,
      connectionDurationMs: body.connectionDurationMs,
      reconnectAttempt: body.reconnectAttempt,
      errorMessage: body.errorMessage,
      metadata: {
        ...body.metadata,
        userAgent: c.req.header('User-Agent'),
        ip: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For'),
      },
    });

    console.log('[Bridge Heartbeat]', {
      edgeId: bridgeEdge.id,
      edgeType: bridgeEdge.type,
      status: body.status,
      previousStatus: body.previousStatus,
      eventId,
    });

    // Return server time and any configuration updates
    return c.json({
      success: true,
      eventId,
      serverTime: new Date().toISOString(),
      serverTimestamp: Date.now(),
      // Optional: return any server configuration updates
      config: {
        heartbeatInterval: 30000, // 30 seconds
        healthCheckInterval: 15000, // 15 seconds
        maxSilenceMs: 60000, // 60 seconds
      },
    });

  } catch (error) {
    console.error('[Bridge Heartbeat] Error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to process heartbeat' 
    }, 500);
  }
});

/**
 * GET /v1/bridge/:edgeId/status - Get current bridge status
 * 
 * Returns the most recent status for a bridge edge.
 * 
 * Authentication: X25519 secret key in Authorization header
 */
bridgeRoutes.get('/:edgeId/status', async (c) => {
  try {
    // Verify authentication
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ 
        code: 'AUTH_REQUIRED', 
        message: 'Authorization header required' 
      }, 401);
    }

    const secretKeyBase64 = authHeader.substring(7);
    const edgeId = c.req.param('edgeId');
    
    // Decode secret key and derive public key
    let derivedPublicKeyBase64: string;
    try {
      const secretKey = fromBase64(secretKeyBase64);
      const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
      derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    } catch (error) {
      return c.json({ 
        code: 'INVALID_KEY', 
        message: 'Invalid secret key format' 
      }, 401);
    }

    // Verify edge exists and user has access
    const edge = await db
      .select()
      .from(edges)
      .where(eq(edges.id, edgeId))
      .limit(1);

    if (edge.length === 0) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: 'Edge not found' 
      }, 404);
    }

    // Verify the secret key matches this edge
    if (edge[0].x25519PublicKey !== derivedPublicKeyBase64) {
      return c.json({ 
        code: 'UNAUTHORIZED', 
        message: 'You do not have access to this edge' 
      }, 403);
    }

    // Get current status
    const status = await getCurrentBridgeStatus(edgeId);

    return c.json({
      edgeId,
      currentStatus: status,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    console.error('[Bridge Status] Error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to get bridge status' 
    }, 500);
  }
});

/**
 * GET /v1/bridge/:edgeId/history - Get bridge status history
 * 
 * Returns recent status events for a bridge edge.
 * 
 * Query parameters:
 * - limit: Number of events to return (default: 100, max: 500)
 * - since: ISO timestamp to filter events after
 * 
 * Authentication: X25519 secret key in Authorization header
 */
bridgeRoutes.get('/:edgeId/history', async (c) => {
  try {
    // Verify authentication
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ 
        code: 'AUTH_REQUIRED', 
        message: 'Authorization header required' 
      }, 401);
    }

    const secretKeyBase64 = authHeader.substring(7);
    const edgeId = c.req.param('edgeId');
    
    // Decode secret key and derive public key
    let derivedPublicKeyBase64: string;
    try {
      const secretKey = fromBase64(secretKeyBase64);
      const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
      derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    } catch (error) {
      return c.json({ 
        code: 'INVALID_KEY', 
        message: 'Invalid secret key format' 
      }, 401);
    }

    const limit = Math.min(parseInt(c.req.query('limit') || '100'), 500);
    const sinceParam = c.req.query('since');
    const since = sinceParam ? new Date(sinceParam) : undefined;

    // Verify edge exists and user has access
    const edge = await db
      .select()
      .from(edges)
      .where(eq(edges.id, edgeId))
      .limit(1);

    if (edge.length === 0) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: 'Edge not found' 
      }, 404);
    }

    // Verify the secret key matches this edge
    if (edge[0].x25519PublicKey !== derivedPublicKeyBase64) {
      return c.json({ 
        code: 'UNAUTHORIZED', 
        message: 'You do not have access to this edge' 
      }, 403);
    }

    // Get status history
    const history = await getBridgeStatusHistory({
      edgeId,
      limit,
      since,
    });

    return c.json({
      edgeId,
      events: history,
      count: history.length,
    });

  } catch (error) {
    console.error('[Bridge History] Error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to get bridge history' 
    }, 500);
  }
});

/**
 * GET /v1/bridge/:edgeId/uptime - Get bridge uptime statistics
 * 
 * Returns uptime statistics for a bridge edge.
 * 
 * Query parameters:
 * - since: ISO timestamp to calculate uptime from (default: 24 hours ago)
 * 
 * Authentication: X25519 secret key in Authorization header
 */
bridgeRoutes.get('/:edgeId/uptime', async (c) => {
  try {
    // Verify authentication
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ 
        code: 'AUTH_REQUIRED', 
        message: 'Authorization header required' 
      }, 401);
    }

    const secretKeyBase64 = authHeader.substring(7);
    const edgeId = c.req.param('edgeId');
    
    // Decode secret key and derive public key
    let derivedPublicKeyBase64: string;
    try {
      const secretKey = fromBase64(secretKeyBase64);
      const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
      derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    } catch (error) {
      return c.json({ 
        code: 'INVALID_KEY', 
        message: 'Invalid secret key format' 
      }, 401);
    }

    const sinceParam = c.req.query('since');
    const since = sinceParam ? new Date(sinceParam) : undefined;

    // Verify edge exists and user has access
    const edge = await db
      .select()
      .from(edges)
      .where(eq(edges.id, edgeId))
      .limit(1);

    if (edge.length === 0) {
      return c.json({ 
        code: 'EDGE_NOT_FOUND', 
        message: 'Edge not found' 
      }, 404);
    }

    // Verify the secret key matches this edge
    if (edge[0].x25519PublicKey !== derivedPublicKeyBase64) {
      return c.json({ 
        code: 'UNAUTHORIZED', 
        message: 'You do not have access to this edge' 
      }, 403);
    }

    // Get uptime statistics
    const stats = await getBridgeUptimeStats({
      edgeId,
      since,
    });

    return c.json({
      edgeId,
      stats,
      since: since?.toISOString() || new Date(Date.now() - 24 * 60 * 60 *1000).toISOString(),
    });

  } catch (error) {
    console.error('[Bridge Uptime] Error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to get bridge uptime' 
    }, 500);
  }
});
