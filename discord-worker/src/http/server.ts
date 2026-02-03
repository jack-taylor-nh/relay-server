/**
 * HTTP Server for Discord Worker
 * 
 * Exposes endpoints for:
 * - GET /public-key - Get worker's X25519 encryption public key
 * - POST /send - Send a Discord DM
 * - GET /health - Health check
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { Client } from 'discord.js';
import { getWorkerPublicKey } from '../crypto.js';
import { handleOutboundDM, SendMessageRequest } from '../handlers/outbound.js';

const API_SECRET = process.env.API_SECRET!;

/**
 * Parse JSON body from request
 */
async function parseBody<T>(req: IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response
 */
function sendJson(res: ServerResponse, status: number, data: object): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(data));
}

/**
 * Verify worker authorization header
 */
function verifyAuth(req: IncomingMessage): boolean {
  const authHeader = req.headers.authorization;
  if (!authHeader) return false;
  
  // Support both "Bearer <secret>" and "Worker <secret>" formats
  const match = authHeader.match(/^(Bearer|Worker)\s+(.+)$/i);
  if (!match) return false;
  
  return match[2] === API_SECRET;
}

/**
 * Create HTTP server
 */
export function createHttpServer(discordClient: Client) {
  return createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);
    
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
      res.end();
      return;
    }
    
    try {
      // GET /health - Health check
      if (url.pathname === '/health' && req.method === 'GET') {
        const botReady = discordClient.isReady();
        sendJson(res, botReady ? 200 : 503, {
          status: botReady ? 'ok' : 'starting',
          botUser: discordClient.user?.tag || null,
          uptime: process.uptime(),
        });
        return;
      }
      
      // GET /public-key - Get worker's encryption public key
      if (url.pathname === '/public-key' && req.method === 'GET') {
        sendJson(res, 200, {
          publicKey: getWorkerPublicKey(),
        });
        return;
      }
      
      // POST /send - Send a Discord DM
      if (url.pathname === '/send' && req.method === 'POST') {
        // Verify authorization
        if (!verifyAuth(req)) {
          sendJson(res, 401, { error: 'Unauthorized' });
          return;
        }
        
        const body = await parseBody<SendMessageRequest>(req);
        
        // Validate required fields
        if (!body.content || !body.recipientDiscordId || !body.edgeAddress) {
          sendJson(res, 400, { error: 'Missing required fields: content, recipientDiscordId, edgeAddress' });
          return;
        }
        
        const result = await handleOutboundDM(discordClient, body);
        
        if (result.success) {
          sendJson(res, 200, result);
        } else {
          sendJson(res, 500, result);
        }
        return;
      }
      
      // 404 for unknown routes
      sendJson(res, 404, { error: 'Not found' });
      
    } catch (error) {
      console.error('HTTP handler error:', error);
      sendJson(res, 500, {
        error: error instanceof Error ? error.message : 'Internal server error',
      });
    }
  });
}
