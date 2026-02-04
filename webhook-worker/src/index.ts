/**
 * Relay Webhook Worker (Express)
 * 
 * Express server that receives webhooks from external services
 * and forwards them to the Relay API for storage
 * 
 * Flow:
 * 1. Receive webhook POST at /w/{edgeId} or /w/{edgeId}?auth={token}
 * 2. Verify authToken (from header or query param)
 * 3. Validate payload schema (sender, title, body required)
 * 4. Encrypt payload for user's edge X25519 key
 * 5. Forward to Relay API /v1/webhook/inbound
 */

import express, { Request, Response } from 'express';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { WebhookPayload, validatePayload, EdgeInfo } from './types.js';
import { createHash } from 'crypto';

const { encodeBase64, decodeBase64 } = naclUtil;

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables
const API_BASE_URL = process.env.API_BASE_URL || process.env.RELAY_API_URL || 'http://localhost:8787';
const API_SECRET = process.env.API_SECRET || '';
const WORKER_ENCRYPTION_PRIVATE_KEY = process.env.WORKER_ENCRYPTION_PRIVATE_KEY || '';
const WORKER_PRIVATE_KEY = process.env.WORKER_PRIVATE_KEY || '';

// Middleware
app.use(express.json({ limit: '100kb' }));

// CORS middleware for debugging/testing
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'relay-webhook-worker'
  });
});

// GET /public-key - Get worker's X25519 public key (for setup/debugging)
app.get('/public-key', (req, res) => {
  try {
    const privateKeyHex = WORKER_ENCRYPTION_PRIVATE_KEY;
    if (!privateKeyHex) {
      return res.status(500).json({ error: 'Worker encryption key not configured' });
    }
    
    const privateKeyBytes = hexToBytes(privateKeyHex);
    const keypair = nacl.box.keyPair.fromSecretKey(privateKeyBytes);
    
    res.json({ 
      publicKey: encodeBase64(keypair.publicKey)
    });
  } catch (error) {
    console.error('Public key error:', error);
    res.status(500).json({ 
      error: 'Failed to get public key' 
    });
  }
});

// POST /w/{edgeId} - Receive webhook
app.post('/w/:edgeId', async (req, res) => {
  try {
    const { edgeId } = req.params;
    
    // 1. Extract auth token (from header or query param)
    const authToken = 
      req.headers.authorization?.replace(/^Bearer\s+/i, '') ||
      req.query.auth as string;
    
    if (!authToken) {
      return res.status(401).json({ 
        error: 'Missing authentication token',
        hint: 'Include Authorization: Bearer {token} header or ?auth={token} query param'
      });
    }
    
    // 2. Validate payload
    const validation = validatePayload(req.body);
    if (!validation.valid) {
      return res.status(400).json({ 
        error: validation.error 
      });
    }
    
    const webhookData = validation.data!;
    
    // 3. Lookup edge from API (verify it exists and get X25519 key)
    const edgeInfo = await lookupEdge(edgeId);
    if (!edgeInfo) {
      return res.status(404).json({ 
        error: 'Webhook edge not found' 
      });
    }
    
    if (edgeInfo.status !== 'active') {
      return res.status(410).json({ 
        error: 'Webhook edge is disabled' 
      });
    }
    
    // 4. Verify auth token matches edge's stored token
    if (edgeInfo.authToken !== authToken) {
      return res.status(401).json({ 
        error: 'Invalid authentication token' 
      });
    }
    
    // 5. Hash sender for privacy (deterministic for conversation matching)
    const senderHash = hashSender(webhookData.sender, edgeId);
    
    // 6. Encrypt payload for user's edge X25519 key
    const encryptedPayload = encryptWebhookPayload(webhookData, edgeInfo.x25519PublicKey);
    
    // 7. Encrypt metadata (sender info) for conversation list display
    const encryptedMetadata = encryptMetadata(webhookData, edgeInfo.x25519PublicKey);
    
    // 8. Forward to API
    await forwardToApi(edgeId, webhookData.sender, senderHash, encryptedPayload, encryptedMetadata);
    
    res.json({ 
      success: true,
      message: 'Webhook received and forwarded' 
    });
    
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

/**
 * Lookup edge from API
 */
async function lookupEdge(edgeId: string): Promise<EdgeInfo | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/edge/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'webhook',
        address: edgeId,
      }),
    });
    
    if (!response.ok) {
      return null;
    }
    
    const data: any = await response.json();
    return {
      edgeId: data.edgeId,
      type: data.type,
      status: data.status,
      securityLevel: data.securityLevel,
      x25519PublicKey: data.x25519PublicKey,
      authToken: data.authToken,  // Webhook edges include authToken
    };
  } catch (error) {
    console.error('Edge lookup failed:', error);
    return null;
  }
}

/**
 * Hash sender for privacy (synchronous version using Node crypto)
 */
function hashSender(sender: string, edgeId: string): string {
  return createHash('sha256')
    .update(`${sender}:${edgeId}`)
    .digest('hex');
}

/**
 * Encrypt webhook payload for user's X25519 key
 */
function encryptWebhookPayload(payload: WebhookPayload, recipientX25519PubKey: string): string {
  const ephemeralKeypair = nacl.box.keyPair();
  const recipientPubKey = decodeBase64(recipientX25519PubKey);
  const nonce = nacl.randomBytes(24);
  
  const plaintext = JSON.stringify(payload);
  const plaintextBytes = new TextEncoder().encode(plaintext);
  
  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    recipientPubKey,
    ephemeralKeypair.secretKey
  );
  
  // Package: ephemeralPubKey:nonce:ciphertext (all base64)
  return `${encodeBase64(ephemeralKeypair.publicKey)}:${encodeBase64(nonce)}:${encodeBase64(ciphertext)}`;
}

/**
 * Encrypt metadata for conversation list display
 */
function encryptMetadata(payload: WebhookPayload, recipientX25519PubKey: string): string {
  const metadata = {
    sender: payload.sender,
    title: payload.title,
  };
  
  const ephemeralKeypair = nacl.box.keyPair();
  const recipientPubKey = decodeBase64(recipientX25519PubKey);
  const nonce = nacl.randomBytes(24);
  
  const plaintext = JSON.stringify(metadata);
  const plaintextBytes = new TextEncoder().encode(plaintext);
  
  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    recipientPubKey,
    ephemeralKeypair.secretKey
  );
  
  return `${encodeBase64(ephemeralKeypair.publicKey)}:${encodeBase64(nonce)}:${encodeBase64(ciphertext)}`;
}

/**
 * Forward webhook to API
 */
async function forwardToApi(
  edgeId: string,
  sender: string,
  senderHash: string,
  encryptedPayload: string,
  encryptedMetadata: string
): Promise<void> {
  const timestamp = new Date().toISOString();
  
  const payload = {
    edgeId,
    sender,
    senderHash,
    encryptedPayload,
    encryptedMetadata,
    receivedAt: timestamp,
  };
  
  // Sign payload for authenticity
  let workerSignature: string | undefined;
  if (WORKER_PRIVATE_KEY) {
    const messageToSign = JSON.stringify(payload);
    workerSignature = signPayload(messageToSign, WORKER_PRIVATE_KEY);
  }
  
  const response = await fetch(`${API_BASE_URL}/v1/webhook/inbound`, {
    method: 'POST',
    headers: {
      'Authorization': `Worker ${API_SECRET}`,
      'Content-Type': 'application/json',
      'X-Worker-Signature': workerSignature || '',
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API forwarding failed: ${response.status} - ${errorText}`);
  }
}

/**
 * Sign payload with Ed25519 key
 */
function signPayload(message: string, privateKeyHex: string): string {
  const messageBytes = new TextEncoder().encode(message);
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
  return encodeBase64(signature);
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Relay Webhook Worker listening on port ${PORT}`);
  console.log(`📡 API Base URL: ${API_BASE_URL}`);
  console.log(`🔐 Encryption configured: ${WORKER_ENCRYPTION_PRIVATE_KEY ? 'Yes' : 'No'}`);
  console.log(`✍️  Signing configured: ${WORKER_PRIVATE_KEY ? 'Yes' : 'No'}`);
});