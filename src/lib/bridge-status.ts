/**
 * Bridge Status Tracking
 * 
 * Helpers for logging and querying bridge connection status events.
 * Used for monitoring bridge health, debugging connection issues, and analytics.
 */

import { db } from '../db/index.js';
import { bridgeStatusEvents, type BridgeStatus, type NewBridgeStatusEvent } from '../db/schema.js';
import { eq, desc, and, gte, sql } from 'drizzle-orm';
import { ulid } from 'ulid';

export interface BridgeStatusMetadata {
  clientType?: 'extension' | 'relay-station' | 'mobile' | 'unknown';
  clientVersion?: string;
  userAgent?: string;
  networkState?: 'online' | 'offline' | 'unknown';
  latencyMs?: number;
  [key: string]: any;
}

/**
 * Log a bridge status change event
 */
export async function logBridgeStatus(params: {
  edgeId: string;
  status: BridgeStatus;
  previousStatus?: BridgeStatus;
  connectionDurationMs?: number;
  reconnectAttempt?: number;
  errorMessage?: string;
  metadata?: BridgeStatusMetadata;
}): Promise<string> {
  const eventId = ulid();
  
  const newEvent: NewBridgeStatusEvent = {
    id: eventId,
    edgeId: params.edgeId,
    status: params.status,
    previousStatus: params.previousStatus || null,
    timestamp: new Date(),
    connectionDurationMs: params.connectionDurationMs || null,
    reconnectAttempt: params.reconnectAttempt || null,
    errorMessage: params.errorMessage || null,
    metadata: params.metadata || {},
  };

  await db.insert(bridgeStatusEvents).values(newEvent);
  
  console.log('[BridgeStatus] Event logged', {
    eventId,
    edgeId: params.edgeId,
    status: params.status,
    previousStatus: params.previousStatus,
  });

  return eventId;
}

/**
 * Get the current (most recent) status for a bridge edge
 */
export async function getCurrentBridgeStatus(edgeId: string): Promise<BridgeStatus | null> {
  const result = await db
    .select({ status: bridgeStatusEvents.status })
    .from(bridgeStatusEvents)
    .where(eq(bridgeStatusEvents.edgeId, edgeId))
    .orderBy(desc(bridgeStatusEvents.timestamp))
    .limit(1);

  return result[0]?.status || null;
}

/**
 * Get bridge status history for an edge
 */
export async function getBridgeStatusHistory(params: {
  edgeId: string;
  limit?: number;
  since?: Date;
}) {
  const { edgeId, limit = 100, since } = params;

  const conditions = [eq(bridgeStatusEvents.edgeId, edgeId)];
  
  if (since) {
    conditions.push(gte(bridgeStatusEvents.timestamp, since));
  }

  const events = await db
    .select()
    .from(bridgeStatusEvents)
    .where(and(...conditions))
    .orderBy(desc(bridgeStatusEvents.timestamp))
    .limit(limit);

  return events;
}

/**
 * Get bridge uptime statistics
 */
export async function getBridgeUptimeStats(params: {
  edgeId: string;
  since?: Date;
}) {
  const { edgeId, since = new Date(Date.now() - 24 * 60 * 60 * 1000) } = params; // Default: last 24h

  const events = await db
    .select()
    .from(bridgeStatusEvents)
    .where(
      and(
        eq(bridgeStatusEvents.edgeId, edgeId),
        gte(bridgeStatusEvents.timestamp, since)
      )
    )
    .orderBy(bridgeStatusEvents.timestamp);

  if (events.length === 0) {
    return {
      totalTime: 0,
      connectedTime: 0,
      uptimePercentage: 0,
      connectionCount: 0,
      averageConnectionDuration: 0,
      failureCount: 0,
    };
  }

  let connectedTime = 0;
  let connectionCount = 0;
  let failureCount = 0;
  let totalConnectionDuration = 0;

  // Track time in connected state
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    
    if (event.status === 'connected') {
      connectionCount++;
      
      // Find next status change
      const nextEvent = events[i + 1];
      if (nextEvent && nextEvent.previousStatus === 'connected') {
        const duration = nextEvent.timestamp.getTime() - event.timestamp.getTime();
        connectedTime += duration;
        totalConnectionDuration += duration;
      }
    }
    
    if (event.status === 'failed') {
      failureCount++;
    }
  }

  const totalTime = Date.now() - since.getTime();
  const uptimePercentage = totalTime > 0 ? (connectedTime / totalTime) * 100 : 0;
  const averageConnectionDuration = connectionCount > 0 ? totalConnectionDuration / connectionCount : 0;

  return {
    totalTime,
    connectedTime,
    uptimePercentage: Math.round(uptimePercentage * 100) / 100,
    connectionCount,
    averageConnectionDuration: Math.round(averageConnectionDuration),
    failureCount,
  };
}

/**
 * Get all failed connection attempts for debugging
 */
export async function getFailedConnections(params: {
  edgeId?: string;
  limit?: number;
  since?: Date;
}) {
  const { edgeId, limit = 50, since = new Date(Date.now() - 24 * 60 * 60 * 1000) } = params;

  const conditions = [
    eq(bridgeStatusEvents.status, 'failed'),
    gte(bridgeStatusEvents.timestamp, since)
  ];

  if (edgeId) {
    conditions.push(eq(bridgeStatusEvents.edgeId, edgeId));
  }

  return await db
    .select()
    .from(bridgeStatusEvents)
    .where(and(...conditions))
    .orderBy(desc(bridgeStatusEvents.timestamp))
    .limit(limit);
}

/**
 * Clean up old bridge status events (for maintenance)
 * Keeps last N days of events
 */
export async function cleanupOldBridgeStatusEvents(daysToKeep: number = 30): Promise<number> {
  const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
  
  const result = await db
    .delete(bridgeStatusEvents)
    .where(sql`${bridgeStatusEvents.timestamp} < ${cutoffDate}`)
    .returning({ id: bridgeStatusEvents.id });

  console.log('[BridgeStatus] Cleanup complete', {
    deleted: result.length,
    cutoffDate: cutoffDate.toISOString(),
  });

  return result.length;
}
