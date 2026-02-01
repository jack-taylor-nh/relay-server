/**
 * Relay Email Worker
 * 
 * Cloudflare Email Worker that receives emails sent to @rlymsg.com aliases
 * and forwards them to the Relay API for processing.
 * 
 * Flow:
 * 1. Receive email at xyz123@rlymsg.com
 * 2. Look up edge by address to verify it exists and is active
 * 3. Forward email content to API for storage as a gateway-secured message
 */

import PostalMime from 'postal-mime';

interface Env {
  API_BASE_URL: string;
  API_SECRET: string; // Shared secret for worker-to-API auth
  EDGE_CACHE: KVNamespace;
}

interface EdgeInfo {
  id: string;
  identityId: string;
  type: string;
  securityLevel: string;
  publicKey: string;
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
 * Look up edge info from API (with KV caching)
 */
async function lookupEdge(address: string, env: Env): Promise<EdgeInfo | null> {
  // Check cache first
  const cached = await env.EDGE_CACHE.get(`edge:${address}`, 'json');
  if (cached) {
    return cached as EdgeInfo;
  }
  
  // Fetch from API
  try {
    const response = await fetch(`${env.API_BASE_URL}/v1/edge/lookup/${encodeURIComponent(address)}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    if (!response.ok) {
      if (response.status === 404 || response.status === 410) {
        // Cache negative result for 5 minutes
        await env.EDGE_CACHE.put(`edge:${address}`, 'null', { expirationTtl: 300 });
        return null;
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    const edgeInfo = await response.json() as EdgeInfo;
    
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
 * Hash an email address for privacy (we don't store raw emails)
 */
async function hashEmail(email: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(email.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Forward email to API for storage
 */
async function forwardToApi(
  address: string,
  edgeInfo: EdgeInfo,
  email: ParsedEmail,
  env: Env
): Promise<void> {
  // Hash the sender's email for privacy
  const fromAddressHash = await hashEmail(email.from);
  
  const payload = {
    edgeId: edgeInfo.id,
    identityId: edgeInfo.identityId,
    email: {
      fromAddressHash,
      fromName: email.fromName,
      subject: email.subject,
      textBody: email.textBody,
      messageId: email.messageId,
      inReplyTo: email.inReplyTo,
      receivedAt: new Date().toISOString(),
    },
  };
  
  const response = await fetch(`${env.API_BASE_URL}/v1/email/inbound`, {
    method: 'POST',
    headers: {
      'Authorization': `Worker ${env.API_SECRET}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API forward error: ${response.status} - ${error}`);
  }
}
