/**
 * Redis Connection & Utilities for Discord Worker
 * 
 * Provides caching for handle lookups to reduce API calls
 */

import Redis from 'ioredis';

// Create Redis client (singleton)
let redisClient: Redis | null = null;

/**
 * Get or create Redis connection
 * Falls back gracefully if Redis is not configured
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

/**
 * Cache-aside pattern helper
 * Tries cache first, falls back to provided function, caches result
 */
export async function getCached<T>(
  key: string,
  ttlSeconds: number,
  fetchFn: () => Promise<T>
): Promise<T> {
  const redis = getRedis();
  
  // No Redis - always fetch fresh
  if (!redis) {
    return fetchFn();
  }

  try {
    // Try cache first
    const cached = await redis.get(key);
    
    if (cached) {
      console.log(`[Redis] Cache HIT: ${key}`);
      return JSON.parse(cached) as T;
    }
    
    console.log(`[Redis] Cache MISS: ${key}`);
    
    // Cache miss - fetch fresh data
    const data = await fetchFn();
    
    // Store in cache with TTL
    await redis.setex(key, ttlSeconds, JSON.stringify(data));
    
    return data;
  } catch (err) {
    console.error('[Redis] Cache operation failed:', err);
    // Fallback to fetch on error
    return fetchFn();
  }
}

/**
 * Invalidate cache by pattern or exact key
 */
export async function invalidateCache(pattern: string): Promise<void> {
  const redis = getRedis();
  if (!redis) return;

  try {
    if (pattern.includes('*')) {
      // Wildcard pattern - use SCAN for safety
      const keys: string[] = [];
      let cursor = '0';
      
      do {
        const [nextCursor, foundKeys] = await redis.scan(
          cursor,
          'MATCH',
          pattern,
          'COUNT',
          100
        );
        cursor = nextCursor;
        keys.push(...foundKeys);
      } while (cursor !== '0');
      
      if (keys.length > 0) {
        await redis.del(...keys);
        console.log(`[Redis] Invalidated ${keys.length} keys matching: ${pattern}`);
      }
    } else {
      // Exact key
      await redis.del(pattern);
      console.log(`[Redis] Invalidated: ${pattern}`);
    }
  } catch (err) {
    console.error('[Redis] Failed to invalidate cache:', err);
  }
}
