/**
 * Static Assets Routes
 * 
 * Serves static assets (icons, images) with proper caching headers
 * for Cloudflare CDN edge caching.
 */

import { Hono } from 'hono';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

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
