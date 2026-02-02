/**
 * Relay Email Worker
 * 
 * Cloudflare Email Worker that receives emails sent to @rlymsg.com aliases
 * and forwards them to the Relay API for processing.
 * 
 * Flow:
 * 1. Receive email at xyz123@rlymsg.com
 * 2. Look up edge by address to verify it exists and is active
 * 3. Encrypt sender email with recipient's public key (zero-knowledge)
 * 4. Forward email content to API for storage as a gateway-secured message
 */

import PostalMime from 'postal-mime';
import * as nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';

interface Env {
  API_BASE_URL: string;
  API_SECRET: string; // Shared secret for worker-to-API auth
  WORKER_PRIVATE_KEY: string; // Ed25519 private key for signing payloads
  WORKER_ENCRYPTION_PRIVATE_KEY: string; // X25519 private key for decrypting recipient emails
  RESEND_API_KEY: string; // Resend API key for sending emails
  EDGE_CACHE: KVNamespace;
  RATCHET_STATES: KVNamespace; // KV storage for Double Ratchet states
}

interface EdgeInfo {
  id: string;
  type: string;
  status: string;
  securityLevel: string;
  x25519PublicKey: string;  // Phase 5: Use edge-specific X25519 key
  displayName?: string;
}

interface ParsedEmail {
  from: string;
  fromName?: string;
  subject: string;
  textBody: string;
  htmlBody?: string;
  messageId?: string;
  inReplyTo?: string;
}

interface EncryptedEmailPackage {
  senderHash: string;           // For conversation matching
  encryptedPayload: string;     // Entire email encrypted
  timestamp: string;
  workerSignature?: string;     // Ed25519 signature over payload
}

interface EmailMessage {
  from: string;
  to: string;
  raw: ReadableStream<Uint8Array>;
}

/**
 * Main email handler
 */
export default {
  async email(message: EmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log(`📧 Received email for: ${message.to}`);
    
    try {
      // Extract alias address from recipient
      const aliasAddress = extractAliasAddress(message.to);
      
      if (!aliasAddress) {
        console.log('Invalid recipient format, rejecting');
        return;
      }
      
      // Look up edge by address (with caching)
      const edgeInfo = await lookupEdge(aliasAddress, env);
      
      if (!edgeInfo) {
        console.log(`Edge not found: ${aliasAddress}`);
        // For privacy, we silently drop unknown aliases
        return;
      }
      
      // Parse email content
      const parsedEmail = await parseEmail(message);
      
      // Forward to API for processing
      await forwardToApi(aliasAddress, edgeInfo, parsedEmail, env);
      
      console.log(`✅ Email processed for edge: ${edgeInfo.id}`);
    } catch (error) {
      console.error('Email processing error:', error);
      // Don't throw - we don't want to bounce emails on errors
    }
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // Handle outbound ratchet-encrypted messages
    if (url.pathname === '/api/send-ratchet' && request.method === 'POST') {
      return handleSendRatchetEmail(request, env);
    }
    
    // CORS headers for client requests
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // GET /public-key - Get worker's encryption public key
    if (url.pathname === '/public-key' && request.method === 'GET') {
      try {
        const privateKeyHex = env.WORKER_ENCRYPTION_PRIVATE_KEY;
        const privateKeyBytes = hexToBytes(privateKeyHex);
        const keypair = nacl.box.keyPair.fromSecretKey(privateKeyBytes);
        
        return new Response(JSON.stringify({ 
          publicKey: encodeBase64(keypair.publicKey)
        }), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (error) {
        console.error('Public key error:', error);
        return new Response(JSON.stringify({ 
          error: 'Failed to get public key' 
        }), { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        });
      }
    }
    
    // POST /send - Send email via Resend
    if (url.pathname === '/send' && request.method === 'POST') {
      try {
        return await handleSendEmail(request, env, corsHeaders);
      } catch (error) {
        console.error('Send email error:', error);
        return new Response(JSON.stringify({ 
          error: error instanceof Error ? error.message : 'Send failed' 
        }), { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        });
      }
    }
    
    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
};

/**
 * Extract full alias address from email address (handles +tags, etc.)
 */
function extractAliasAddress(address: string): string | null {
  // Handle format: xyz123@rlymsg.com
  const match = address.match(/^([a-z0-9]+)@rlymsg\.com$/i);
  return match ? `${match[1].toLowerCase()}@rlymsg.com` : null;
}

/**
 * Look up edge info from API using unified resolution (with KV caching)
 * Phase 5: Uses POST /v1/edge/resolve for proper edge-to-edge encryption
 */
async function lookupEdge(address: string, env: Env): Promise<EdgeInfo | null> {
  // Check cache first
  const cached = await env.EDGE_CACHE.get(`edge:${address}`, 'json');
  if (cached) {
    return cached as EdgeInfo;
  }
  
  // Determine edge type from address format
  const edgeType = address.includes('@') ? 'email' : 'native';
  
  // Use unified edge resolution endpoint
  try {
    const response = await fetch(`${env.API_BASE_URL}/v1/edge/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: edgeType,
        address: address,
      }),
    });
    
    if (!response.ok) {
      if (response.status === 404 || response.status === 410) {
        // Cache negative result for 5 minutes
        await env.EDGE_CACHE.put(`edge:${address}`, 'null', { expirationTtl: 300 });
        return null;
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json() as {
      edgeId: string;
      type: string;
      status: string;
      securityLevel: string;
      x25519PublicKey: string;
      displayName?: string;
    };
    
    // Map to EdgeInfo format
    const edgeInfo: EdgeInfo = {
      id: data.edgeId,
      type: data.type,
      status: data.status,
      securityLevel: data.securityLevel,
      x25519PublicKey: data.x25519PublicKey,
      displayName: data.displayName,
    };
    
    // Cache for 1 hour
    await env.EDGE_CACHE.put(`edge:${address}`, JSON.stringify(edgeInfo), { 
      expirationTtl: 3600 
    });
    
    return edgeInfo;
  } catch (error) {
    console.error('Edge lookup error:', error);
    return null;
  }
}

/**
 * Parse raw email using postal-mime
 */
async function parseEmail(message: EmailMessage): Promise<ParsedEmail> {
  // Read the raw email stream
  const rawEmail = await new Response(message.raw).arrayBuffer();
  const parser = new PostalMime();
  const parsed = await parser.parse(rawEmail);
  
  return {
    from: parsed.from?.address || message.from,
    fromName: parsed.from?.name,
    subject: parsed.subject || '(no subject)',
    textBody: parsed.text || '',
    htmlBody: parsed.html,
    messageId: parsed.messageId,
    inReplyTo: parsed.inReplyTo,
  };
}

/**
 * Hash an email address for privacy (deterministic for conversation matching)
 */
async function hashEmail(email: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(email.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encrypt entire email payload with recipient's edge X25519 public key (zero-knowledge)
 * Phase 5: Uses edge-specific X25519 key, not identity-derived key
 * Only the recipient's edge can decrypt this
 */
function encryptEmailPayload(email: ParsedEmail, publicKeyBase64: string): string {
  try {
    // Decode recipient's edge X25519 encryption public key
    const recipientPublicKey = decodeBase64(publicKeyBase64);
    
    // Generate ephemeral keypair for encryption
    const ephemeralKeyPair = nacl.box.keyPair();
    
    // Serialize entire email as JSON
    const emailJson = JSON.stringify({
      from: email.from,
      fromName: email.fromName,
      subject: email.subject,
      textBody: email.textBody,
      htmlBody: email.htmlBody,
      messageId: email.messageId,
      inReplyTo: email.inReplyTo,
    });
    const messageBytes = new TextEncoder().encode(emailJson);
    
    // Generate nonce
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    
    // Encrypt with box (authenticated encryption)
    const encrypted = nacl.box(
      messageBytes,
      nonce,
      recipientPublicKey,
      ephemeralKeyPair.secretKey
    );
    
    // Package as: ephemeralPublicKey:nonce:ciphertext (all base64)
    const pkg = {
      ephemeralPubkey: encodeBase64(ephemeralKeyPair.publicKey),
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(encrypted),
    };
    
    return JSON.stringify(pkg);
  } catch (error) {
    console.error('Encryption error:', error);
    throw error;
  }
}

/**
 * Forward email to API for storage
 * Phase 5: Encrypts to user's edge-specific X25519 key (not identity-derived)
 */
async function forwardToApi(
  address: string,
  edgeInfo: EdgeInfo,
  email: ParsedEmail,
  env: Env
): Promise<void> {
  // Hash sender email BEFORE encryption (for deterministic conversation matching)
  const senderHash = await hashEmail(email.from);
  
  // Encrypt entire email payload with recipient's edge X25519 public key (zero-knowledge)
  // Phase 5: Use edge-specific key, not identity-derived key
  const encryptedPayload = encryptEmailPayload(email, edgeInfo.x25519PublicKey);
  
  const timestamp = new Date().toISOString();
  
  const payload = {
    edgeId: edgeInfo.id,
    senderHash,                     // Deterministic hash for matching
    encryptedPayload,               // Full email encrypted (server can't read)
    receivedAt: timestamp,
  };
  
  // Sign payload to prevent injection attacks
  let workerSignature: string | undefined;
  if (env.WORKER_PRIVATE_KEY) {
    const messageToSign = `${edgeInfo.id}:${senderHash}:${encryptedPayload}:${timestamp}`;
    workerSignature = await signPayload(messageToSign, env.WORKER_PRIVATE_KEY);
  }
  
  const response = await fetch(`${env.API_BASE_URL}/v1/email/inbound`, {
    method: 'POST',
    headers: {
      'Authorization': `Worker ${env.API_SECRET}`,
      'Content-Type': 'application/json',
      'X-Worker-Signature': workerSignature || '',
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API forward error: ${response.status} - ${error}`);
  }
}

/**
 * Sign payload with worker's private key (Ed25519)
 */
async function signPayload(message: string, privateKeyHex: string): Promise<string> {
  try {
    const privateKeyBytes = hexToBytes(privateKeyHex);
    const messageBytes = new TextEncoder().encode(message);
    const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
    return encodeBase64(signature);
  } catch (error) {
    console.error('Signature error:', error);
    throw error;
  }
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

/**
 * Decrypt recipient email address using worker's X25519 private key
 * Client encrypts: ephemeralPubkey:nonce:ciphertext (all base64)
 */
function decryptRecipient(encryptedPackage: string, privateKeyHex: string): string {
  try {
    const parts = encryptedPackage.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted package format');
    }

    const ephemeralPubkey = decodeBase64(parts[0]);
    const nonce = decodeBase64(parts[1]);
    const ciphertext = decodeBase64(parts[2]);

    // Derive worker's keypair from private key
    const workerPrivateKey = hexToBytes(privateKeyHex);
    const workerKeypair = nacl.box.keyPair.fromSecretKey(workerPrivateKey);

    // Decrypt using box (X25519-XSalsa20-Poly1305)
    const decrypted = nacl.box.open(
      ciphertext,
      nonce,
      ephemeralPubkey,
      workerKeypair.secretKey
    );

    if (!decrypted) {
      throw new Error('Decryption failed - invalid ciphertext or key');
    }

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error('Recipient decryption error:', error);
    throw error;
  }
}

/**
 * Handle sending email via MailChannels (zero-knowledge)
 * 
 * Flow:
 * 1. Client sends: conversationId, content, encryptedRecipient (encrypted for worker)
 * 2. Worker looks up edge info from API
 * 3. Worker decrypts recipient email temporarily in memory
 * 4. Worker sends via MailChannels
 * 5. Worker purges decrypted data
 */
async function handleSendEmail(
  request: Request,
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const body = await request.json() as {
    conversationId: string;
    content: string;
    encryptedRecipient: string;  // Encrypted for worker's X25519 key (base64: ephemeralPubkey:nonce:ciphertext)
    edgeAddress: string;          // From address (e.g., xyz123@rlymsg.com)
    subject: string;
    inReplyTo?: string;
  };

  if (!body.conversationId || !body.content || !body.encryptedRecipient || !body.edgeAddress) {
    return new Response(JSON.stringify({ error: 'Missing required fields' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    // Decrypt recipient email with worker's private key (zero-knowledge!)
    const recipientEmail = decryptRecipient(body.encryptedRecipient, env.WORKER_ENCRYPTION_PRIVATE_KEY);
    
    // Build Resend API request
    const resendPayload: any = {
      from: `Relay <${body.edgeAddress}>`,
      to: [recipientEmail],
      subject: body.subject,
      text: body.content,
    };

    if (body.inReplyTo) {
      resendPayload.headers = {
        'In-Reply-To': body.inReplyTo,
      };
    }

    // Send email via Resend
    const resendResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(resendPayload),
    });

    if (!resendResponse.ok) {
      const error = await resendResponse.text();
      throw new Error(`Resend error: ${resendResponse.status} - ${error}`);
    }

    const result = await resendResponse.json() as { id: string };

    // Purge decrypted recipient from memory (JS GC handles this)
    // In production, could use secure zeroing if available

    return new Response(JSON.stringify({ 
      success: true,
      messageId: result.id, // Resend returns the email ID
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Resend send error:', error);
    throw error;
  }
}

/**
 * Handle sending email with ratchet decryption (unified messaging)
 * 
 * Flow:
 * 1. Server sends: MessageEnvelope with ratchet-encrypted content
 * 2. Worker loads ratchet state from KV
 * 3. Worker decrypts ratchet message
 * 4. Worker decrypts recipient email
 * 5. Worker sends via Resend
 * 6. Worker updates ratchet state in KV
 */
async function handleSendRatchetEmail(
  request: Request,
  env: Env
): Promise<Response> {
  try {
    const body = await request.json() as {
      conversationId: string;
      envelope: {
        payload: {
          content_type: string;
          ratchet: {
            ciphertext: string;
            dh: string;
            pn: number;
            n: number;
            nonce: string;
          };
        };
      };
      encryptedRecipient: string;  // Encrypted for worker
      edgeAddress: string;          // From address
      subject: string;
      inReplyTo?: string;
    };

    if (!body.conversationId || !body.envelope || !body.encryptedRecipient || !body.edgeAddress) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 1. Load ratchet state from KV
    const ratchetStateKey = `ratchet:${body.conversationId}`;
    const serializedState = await env.RATCHET_STATES.get(ratchetStateKey);
    
    if (!serializedState) {
      return new Response(JSON.stringify({ error: 'Ratchet state not found - cannot decrypt' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 2. Deserialize ratchet state (simplified - in production use full deserializeRatchetState)
    const ratchetState = JSON.parse(serializedState);

    // 3. Decrypt ratchet message
    // NOTE: For MVP, we'll decrypt on client side and have server send plaintext to worker
    // Full ratchet implementation in worker requires porting crypto library
    const plaintextContent = await decryptRatchetMessage(body.envelope.payload.ratchet, ratchetState);

    // 4. Decrypt recipient email
    const recipientEmail = decryptRecipient(body.encryptedRecipient, env.WORKER_ENCRYPTION_PRIVATE_KEY);
    
    // 5. Send via Resend
    const resendPayload: any = {
      from: `Relay <${body.edgeAddress}>`,
      to: [recipientEmail],
      subject: body.subject,
      text: plaintextContent,
    };

    if (body.inReplyTo) {
      resendPayload.headers = {
        'In-Reply-To': body.inReplyTo,
      };
    }

    const resendResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(resendPayload),
    });

    if (!resendResponse.ok) {
      const error = await resendResponse.text();
      throw new Error(`Resend error: ${resendResponse.status} - ${error}`);
    }

    const result = await resendResponse.json() as { id: string };

    // 6. Update ratchet state (would be updated by decryptRatchetMessage)
    // await env.RATCHET_STATES.put(ratchetStateKey, JSON.stringify(newRatchetState));

    return new Response(JSON.stringify({ 
      success: true,
      messageId: result.id,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Ratchet email send error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to send email',
      details: error instanceof Error ? error.message : 'Unknown error'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Decrypt ratchet message (simplified - requires full Double Ratchet implementation)
 * TODO: Port full ratchet crypto library to worker
 */
async function decryptRatchetMessage(
  ratchetMessage: { ciphertext: string; dh: string; pn: number; n: number; nonce: string },
  ratchetState: any
): Promise<string> {
  // For MVP: Return placeholder
  // In production: Implement full RatchetDecrypt with tweetnacl
  return '[Ratchet decryption pending - requires crypto library port]';
}