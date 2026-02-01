/**
 * Auth Middleware
 * 
 * Validates JWT token and sets fingerprint on context
 */

import { Context, Next } from 'hono';
import { verifySessionToken } from '../lib/jwt.js';

declare module 'hono' {
  interface ContextVariableMap {
    fingerprint: string;
    identityId: string;
  }
}

export async function authMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing or invalid authorization header' }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifySessionToken(token);
    
    if (!payload || !payload.fingerprint) {
      return c.json({ code: 'UNAUTHORIZED', message: 'Invalid token' }, 401);
    }

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return c.json({ code: 'TOKEN_EXPIRED', message: 'Token has expired' }, 401);
    }

    c.set('fingerprint', payload.fingerprint);
    c.set('identityId', payload.fingerprint); // identityId is fingerprint
    await next();
  } catch (error) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Invalid token' }, 401);
  }
}
