/**
 * Static Assets Routes + Asset Redemption
 * 
 * Serves static assets (icons, images) with proper caching headers
 * for Cloudflare CDN edge caching.
 * 
 * Also handles asset code redemption with signature verification
 * and identity-blind double-redemption prevention.
 */

import { Hono } from 'hono';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/index.js';
import { redemptionCodes, redemptionReceipts } from '../db/schema.js';
import { verifyString, fromBase64, computeFingerprint, computeHmac } from '../core/crypto/index.js';
import { generateId } from '../core/crypto/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Assets are in src/assets, which is two levels up from routes/
// In production (dist), this will be dist/routes/ looking for dist/assets/ 
// So we go up one level from routes to find assets
const ASSETS_DIR = join(__dirname, '..', 'assets');

export const assetsRoutes = new Hono();

/**
 * Serve the Relay icon
 * GET /assets/relay-icon.png
 * 
 * Cache headers optimized for Cloudflare CDN:
 * - Cache-Control: public, max-age=31536000, immutable
 * - CDN-Cache-Control: max-age=31536000 (1 year at edge)
 * - Cloudflare will cache this at edge locations globally
 */
assetsRoutes.get('/relay-icon.png', async (c) => {
  try {
    const iconPath = join(ASSETS_DIR, 'relay-icon.png');
    const iconBuffer = await readFile(iconPath);
    
    return new Response(iconBuffer, {
      status: 200,
      headers: {
        'Content-Type': 'image/png',
        // Browser cache: 1 year (immutable means never revalidate)
        'Cache-Control': 'public, max-age=31536000, immutable',
        // Cloudflare-specific: cache at edge for 1 year
        'CDN-Cache-Control': 'max-age=31536000',
        // Cloudflare Cache Tag for purging if needed
        'Cache-Tag': 'relay-assets,relay-icon',
        // ETag for validation
        'ETag': '"relay-icon-v1"',
      },
    });
  } catch (error) {
    console.error('Failed to serve relay icon:', error);
    return c.json({ error: 'Icon not found' }, 404);
  }
});

/**
 * Serve Discord-related assets if needed
 * For now, we use Discord's CDN directly for Discord avatars
 */

// ============================================
// Asset Redemption System
// ============================================

const REDEMPTION_RECEIPT_SECRET = process.env.REDEMPTION_RECEIPT_SECRET || 'relay-redemption-secret-change-in-production';
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX = 10; // 10 requests per hour

// Simple in-memory rate limiter (use Redis in production)
const redemptionRateLimits = new Map<string, { count: number; resetAt: number }>();

/**
 * Check rate limit for IP address
 */
function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = redemptionRateLimits.get(ip);
  
  // No record or expired: allow and create new
  if (!record || now > record.resetAt) {
    redemptionRateLimits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  
  // Under limit: increment and allow
  if (record.count < RATE_LIMIT_MAX) {
    record.count++;
    return true;
  }
  
  // Over limit: deny
  return false;
}

/**
 * POST /v1/assets/redeem
 * 
 * Redeem an asset code (permanent tier or consumable tokens)
 * with identity-blind double-redemption prevention.
 * 
 * Request body:
 * {
 *   code: string,              // Redemption code (XXXX-XXXX-XXXX-XXXX)
 *   publicKey: string,         // Base64-encoded Ed25519 public key
 *   signature: string,         // Base64 Ed25519 signature of code
 *   timestamp: number          // Unix timestamp (ms) for replay protection
 * }
 * 
 * Response:
 * {
 *   success: true,
 *   asset: {
 *     type: 'permanent' | 'consumable',
 *     assetType: string,
 *     value?: number,
 *     metadata: object
 *   }
 * }
 */
assetsRoutes.post('/v1/assets/redeem', async (c) => {
  try {
    // Get client IP for rate limiting
    const ip = c.req.header('cf-connecting-ip') || 
               c.req.header('x-forwarded-for') || 
               c.req.header('x-real-ip') || 
               'unknown';
    
    // Rate limit check
    if (!checkRateLimit(ip)) {
      return c.json({ 
        code: 'RATE_LIMIT_EXCEEDED', 
        message: 'Too many redemption attempts. Please try again later.' 
      }, 429);
    }
    
    // Parse and validate request body
    const body = await c.req.json<{
      code: string;
      publicKey: string;
      signature: string;
      timestamp: number;
    }>();
    
    if (!body.code || !body.publicKey || !body.signature || !body.timestamp) {
      return c.json({ 
        code: 'VALIDATION_ERROR', 
        message: 'Missing required fields: code, publicKey, signature, timestamp' 
      }, 400);
    }
    
    // Replay protection: timestamp must be within 5 minutes
    const now = Date.now();
    const timeDiff = Math.abs(now - body.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return c.json({ 
        code: 'TIMESTAMP_INVALID', 
        message: 'Timestamp too old or too far in future' 
      }, 400);
    }
    
    // Verify Ed25519 signature (sign(code + timestamp))
    const publicKeyBytes = fromBase64(body.publicKey);
    const message = `${body.code}:${body.timestamp}`;
    
    const signatureValid = verifyString(message, body.signature, publicKeyBytes);
    if (!signatureValid) {
      return c.json({ 
        code: 'SIGNATURE_INVALID', 
        message: 'Invalid signature' 
      }, 401);
    }
    
    // Compute identity fingerprint (for receipt key)
    const fingerprint = computeFingerprint(publicKeyBytes);
    
    // Look up redemption code
    const [codeRecord] = await db
      .select()
      .from(redemptionCodes)
      .where(eq(redemptionCodes.code, body.code))
      .limit(1);
    
    if (!codeRecord) {
      return c.json({ 
        code: 'CODE_NOT_FOUND', 
        message: 'Redemption code not found' 
      }, 404);
    }
    
    // Check code status
    if (codeRecord.status !== 'active') {
      return c.json({ 
        code: 'CODE_INVALID', 
        message: `Code is ${codeRecord.status}` 
      }, 400);
    }
    
    // Check expiration
    if (codeRecord.expiresAt && new Date() > codeRecord.expiresAt) {
      // Mark as expired
      await db
        .update(redemptionCodes)
        .set({ status: 'expired' })
        .where(eq(redemptionCodes.id, codeRecord.id));
      
      return c.json({ 
        code: 'CODE_EXPIRED', 
        message: 'Redemption code has expired' 
      }, 400);
    }
    
    // Compute HMAC receipt key: HMAC(fingerprint + codeId, SECRET)
    // This allows double-redemption prevention without storing identity
    const receiptKey = computeHmac(`${fingerprint}:${codeRecord.id}`, REDEMPTION_RECEIPT_SECRET);
    
    // Check if already redeemed by this identity
    const [existingReceipt] = await db
      .select()
      .from(redemptionReceipts)
      .where(eq(redemptionReceipts.receiptKey, receiptKey))
      .limit(1);
    
    if (existingReceipt) {
      return c.json({ 
        code: 'CODE_ALREADY_REDEEMED', 
        message: 'This code has already been redeemed by your identity' 
      }, 400);
    }
    
    // Create redemption receipt and mark code as redeemed
    // Use transaction to ensure atomicity
    const receiptId = generateId();
    const redeemedAt = new Date();
    
    await db.transaction(async (tx) => {
      // Create receipt
      await tx.insert(redemptionReceipts).values({
        id: receiptId,
        receiptKey,
        codeId: codeRecord.id,
        redeemedAt,
      });
      
      // Mark code as redeemed
      await tx
        .update(redemptionCodes)
        .set({ 
          status: 'redeemed', 
          redeemedAt 
        })
        .where(eq(redemptionCodes.id, codeRecord.id));
    });
    
    // Return success with asset details
    return c.json({
      success: true,
      asset: {
        type: codeRecord.type,
        assetType: codeRecord.assetType,
        value: codeRecord.value,
        metadata: codeRecord.metadata,
      },
    });
    
  } catch (error) {
    console.error('Redemption error:', error);
    return c.json({ 
      code: 'INTERNAL_ERROR', 
      message: 'Failed to process redemption' 
    }, 500);
  }
});
