/**
 * JWT utilities for session tokens
 * 
 * Uses a simple HMAC-SHA256 signing scheme.
 * For production, consider using a more robust library.
 */

import { createHmac } from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'relay-dev-secret-change-in-production';

interface TokenPayload {
  fingerprint: string;
  exp: number;
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str: string): string {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return Buffer.from(str, 'base64').toString();
}

export async function signSessionToken(payload: TokenPayload): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  const signature = createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export async function verifySessionToken(token: string): Promise<TokenPayload | null> {
  try {
    const [encodedHeader, encodedPayload, providedSignature] = token.split('.');
    
    if (!encodedHeader || !encodedPayload || !providedSignature) {
      return null;
    }
    
    // Verify signature
    const expectedSignature = createHmac('sha256', JWT_SECRET)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    if (providedSignature !== expectedSignature) {
      return null;
    }
    
    // Decode payload
    const payload = JSON.parse(base64UrlDecode(encodedPayload)) as TokenPayload;
    
    return payload;
  } catch {
    return null;
  }
}
