/**
 * Redis Connection & Utilities
 * 
 * Provides caching, rate limiting, and pub/sub capabilities
 */

import Redis from 'ioredis';

// Create Redis client (singleton)
let redisClient: Redis | null = null;

/**
 * Get or create Redis connection
 * Falls back gracefully if Redis is not configured (for local dev)
 */
export function getRedis(): Redis | null {
  // If Redis is disabled or not configured, return null
  if (process.env.DISABLE_REDIS === 'true' || !process.env.REDIS_URL) {
    if (!redisClient) {
      console.log('[Redis] Disabled or not configured - operating without cache');
    }
    return null;
  }

  // Return existing connection
  if (redisClient) {
    return redisClient;
  }

  // Create new connection
  try {
    redisClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      reconnectOnError: (err) => {
        const targetError = 'READONLY';
        if (err.message.includes(targetError)) {
          // Only reconnect when the error contains "READONLY"
          return true;
        }
        return false;
      },
    });

    redisClient.on('connect', () => {
      console.log('[Redis] Connected successfully');
    });

    redisClient.on('error', (err) => {
      console.error('[Redis] Error:', err.message);
    });

    redisClient.on('ready', () => {
      console.log('[Redis] Ready to accept commands');
    });

    return redisClient;
  } catch (err) {
    console.error('[Redis] Failed to initialize:', err);
    return null;
  }
}

/**
 * Gracefully close Redis connection (for shutdown)
 */
export async function closeRedis(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
    console.log('[Redis] Connection closed');
  }
}

// =============================================================================
// Cache Helpers
// =============================================================================

/**
 * Get cached value with fallback
 * If cache miss, executes fallback function and caches result
 */
export async function getCached<T>(
  key: string,
  ttlSeconds: number,
  fallback: () => Promise<T>
): Promise<T> {
  const redis = getRedis();
  
  // No Redis - just execute fallback
  if (!redis) {
    return fallback();
  }

  try {
    // Try cache first
    const cached = await redis.get(key);
    if (cached) {
      console.log(`[Redis] Cache HIT: ${key}`);
      return JSON.parse(cached) as T;
    }

    console.log(`[Redis] Cache MISS: ${key}`);
    
    // Cache miss - execute fallback
    const result = await fallback();
    
    // Cache result (fire and forget - don't block response)
    redis.setex(key, ttlSeconds, JSON.stringify(result)).catch(err => {
      console.error('[Redis] Failed to cache:', err.message);
    });

    return result;
  } catch (err) {
    console.error('[Redis] Cache error:', err);
    // On error, fallback to direct execution
    return fallback();
  }
}

/**
 * Invalidate cache key(s)
 */
export async function invalidateCache(pattern: string): Promise<void> {
  const redis = getRedis();
  if (!redis) {
    console.log('[Redis] Cache invalidation skipped - Redis not available');
    return;
  }

  try {
    // If exact key (no wildcard)
    if (!pattern.includes('*')) {
      await redis.del(pattern);
      console.log(`[Redis] Invalidated key: ${pattern}`);
      return;
    }

    // Wildcard pattern - scan and delete
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
      console.log(`[Redis] Invalidated ${keys.length} keys matching: ${pattern}`);
    } else {
      console.log(`[Redis] No keys found matching: ${pattern}`);
    }
  } catch (err) {
    console.error('[Redis] Failed to invalidate cache:', err);
  }
}

// =============================================================================
// Rate Limiting
// =============================================================================

/**
 * Check and increment rate limit counter
 * Returns { allowed: boolean, remaining: number }
 */
export async function checkRateLimit(
  key: string,
  maxRequests: number,
  windowSeconds: number
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const redis = getRedis();
  
  // No Redis - allow all requests (fail open)
  if (!redis) {
    return { allowed: true, remaining: maxRequests, resetAt: Date.now() + windowSeconds * 1000 };
  }

  try {
    const current = await redis.incr(key);
    
    // First request - set expiry
    if (current === 1) {
      await redis.expire(key, windowSeconds);
    }

    const ttl = await redis.ttl(key);
    const resetAt = Date.now() + (ttl * 1000);
    const remaining = Math.max(0, maxRequests - current);

    return {
      allowed: current <= maxRequests,
      remaining,
      resetAt,
    };
  } catch (err) {
    console.error('[Redis] Rate limit check failed:', err);
    // On error, allow request (fail open)
    return { allowed: true, remaining: maxRequests, resetAt: Date.now() + windowSeconds * 1000 };
  }
}

/**
 * Reset rate limit for a key
 */
export async function resetRateLimit(key: string): Promise<void> {
  const redis = getRedis();
  if (!redis) return;

  try {
    await redis.del(key);
  } catch (err) {
    console.error('[Redis] Failed to reset rate limit:', err);
  }
}

// =============================================================================
// Distributed Locking
// =============================================================================

/**
 * Acquire distributed lock
 * Returns lock token if successful, null if lock is held
 */
export async function acquireLock(
  key: string,
  ttlSeconds: number = 5
): Promise<string | null> {
  const redis = getRedis();
  
  // No Redis - always succeed (unsafe, but better than blocking)
  if (!redis) {
    return 'no-redis-lock';
  }

  try {
    const lockToken = `${Date.now()}-${Math.random()}`;
    const result = await redis.set(key, lockToken, 'EX', ttlSeconds, 'NX');
    
    return result === 'OK' ? lockToken : null;
  } catch (err) {
    console.error('[Redis] Failed to acquire lock:', err);
    return null;
  }
}

/**
 * Release distributed lock
 */
export async function releaseLock(key: string, token: string): Promise<void> {
  const redis = getRedis();
  if (!redis) return;

  try {
    // Only delete if token matches (prevent releasing someone else's lock)
    const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      else
        return 0
      end
    `;
    await redis.eval(script, 1, key, token);
  } catch (err) {
    console.error('[Redis] Failed to release lock:', err);
  }
}

// =============================================================================
// Pub/Sub (for real-time SSE streaming)
// =============================================================================

// Separate Redis client for pub/sub (can't use same client for commands and subscriptions)
let subscriberClient: Redis | null = null;

/**
 * Get or create subscriber client
 */
function getSubscriber(): Redis | null {
  if (!process.env.REDIS_URL || process.env.DISABLE_REDIS === 'true') {
    return null;
  }

  if (subscriberClient) {
    return subscriberClient;
  }

  try {
    subscriberClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
    });

    subscriberClient.on('error', (err) => {
      console.error('[Redis Subscriber] Error:', err.message);
    });

    return subscriberClient;
  } catch (err) {
    console.error('[Redis Subscriber] Failed to create:', err);
    return null;
  }
}

/**
 * Publish message to channel
 */
export async function publish(channel: string, message: any): Promise<void> {
  const redis = getRedis();
  if (!redis) return;

  try {
    await redis.publish(channel, JSON.stringify(message));
    console.log(`[Redis] Published to ${channel}`);
  } catch (err) {
    console.error('[Redis] Failed to publish:', err);
  }
}

/**
 * Subscribe to channel with message handler
 * Returns unsubscribe function
 */
export async function subscribe(
  channel: string,
  handler: (message: string) => void
): Promise<void> {
  const subscriber = getSubscriber();
  if (!subscriber) {
    console.warn('[Redis] Pub/sub not available - SSE will not work');
    return;
  }

  try {
    // Register message handler
    subscriber.on('message', (ch, message) => {
      if (ch === channel) {
        handler(message);
      }
    });

    // Subscribe to channel
    await subscriber.subscribe(channel);
    console.log(`[Redis] Subscribed to ${channel}`);
  } catch (err) {
    console.error('[Redis] Failed to subscribe:', err);
  }
}

/**
 * Unsubscribe from channel
 */
export async function unsubscribe(
  channel: string,
  handler: (message: string) => void
): Promise<void> {
  const subscriber = getSubscriber();
  if (!subscriber) return;

  try {
    // Remove handler
    subscriber.off('message', handler as any);
    
    // Unsubscribe from channel
    await subscriber.unsubscribe(channel);
    console.log(`[Redis] Unsubscribed from ${channel}`);
  } catch (err) {
    console.error('[Redis] Failed to unsubscribe:', err);
  }
}

/**
 * Close subscriber connection
 */
export async function closeSubscriber(): Promise<void> {
  if (subscriberClient) {
    await subscriberClient.quit();
    subscriberClient = null;
    console.log('[Redis Subscriber] Connection closed');
  }
}
