/**
 * Relay API Client
 * 
 * HTTP client for communicating with the Relay API server
 */

import { signPayload } from './crypto.js';
import { getCached } from './redis.js';

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.rlymsg.com';
const API_SECRET = process.env.API_SECRET!;

export interface EdgeInfo {
  id: string;
  type: string;
  status: string;
  securityLevel: string;
  x25519PublicKey: string;
  displayName?: string;
}

/**
 * Look up edge by Relay handle for Discord
 * Looks for type: 'discord' edges specifically
 * 
 * CACHED: Handle lookups are cached for 1 hour since they rarely change
 */
export async function lookupEdgeByHandle(handle: string): Promise<EdgeInfo | null> {
  const normalizedHandle = handle.toLowerCase();
  const cacheKey = `discord:handle:${normalizedHandle}`;
  
  // Try cache first with 1 hour TTL (3600 seconds)
  // Handles rarely change, so we can cache aggressively
  return getCached(cacheKey, 3600, async () => {
    try {
      // Cache miss - fetch from API
      const response = await fetch(`${API_BASE_URL}/v1/edge/resolve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'discord',  // Discord edges only
          address: normalizedHandle,
        }),
      });
      
      if (!response.ok) {
        if (response.status === 404 || response.status === 410) {
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
      
      return {
        id: data.edgeId,
        type: data.type,
        status: data.status,
        securityLevel: data.securityLevel,
        x25519PublicKey: data.x25519PublicKey,
        displayName: data.displayName,
      };
    } catch (error) {
      console.error('Handle lookup error:', error);
      return null;
    }
  });
}

/**
 * Forward encrypted Discord message to Relay API
 */
export async function forwardToApi(payload: {
  edgeId: string;
  senderHash: string;
  encryptedRecipientId: string;  // Encrypted Discord ID for reply routing (only worker can decrypt)
  encryptedPayload: string;
  encryptedMetadata?: string;     // Encrypted counterparty info for conversation list display
  discordMessageId?: string;      // Discord message ID for reply threading
  receivedAt: string;
}): Promise<{ conversationId: string; messageId: string; isNewConversation: boolean } | undefined> {
  const timestamp = payload.receivedAt;
  
  // Sign payload to prevent injection attacks
  const messageToSign = `${payload.edgeId}:${payload.senderHash}:${payload.encryptedPayload}:${timestamp}`;
  let workerSignature: string | undefined;
  
  try {
    workerSignature = signPayload(messageToSign);
  } catch (error) {
    console.warn('Could not sign payload:', error);
  }
  
  const response = await fetch(`${API_BASE_URL}/v1/discord/inbound`, {
    method: 'POST',
    headers: {
      'Authorization': `Worker ${API_SECRET}`,
      'Content-Type': 'application/json',
      'X-Worker-Signature': workerSignature || '',
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API forward error: ${response.status} - ${error}`);
  }
  
  const result = await response.json() as { conversationId: string; messageId: string; isNewConversation: boolean };
  return result;
}

/**
 * Update the conversation message ID for a conversation
 * This is called after we create the bot's conversation message in Discord
 */
export async function updateConversationMessageId(
  conversationId: string | undefined,
  conversationMessageId: string
): Promise<void> {
  if (!conversationId) {
    console.warn('No conversation ID to update');
    return;
  }
  
  const response = await fetch(`${API_BASE_URL}/v1/discord/conversation-message`, {
    method: 'POST',
    headers: {
      'Authorization': `Worker ${API_SECRET}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      conversationId,
      conversationMessageId,
    }),
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to update conversation message ID: ${response.status} - ${error}`);
  }
}

/**
 * Look up existing conversation for a Discord user + Relay edge
 * Returns conversation info including the conversation message ID if it exists
 */
export async function lookupExistingConversation(
  senderHash: string,
  edgeId: string
): Promise<{
  conversationId: string;
  conversationMessageId?: string;
} | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/discord/lookup-conversation`, {
      method: 'POST',
      headers: {
        'Authorization': `Worker ${API_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        senderHash,
        edgeId,
      }),
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        return null; // No existing conversation
      }
      throw new Error(`API error: ${response.status}`);
    }
    
    return await response.json() as {
      conversationId: string;
      conversationMessageId?: string;
    };
  } catch (error) {
    console.error('Conversation lookup error:', error);
    return null;
  }
}

/**
 * Look up Discord bridge edge public key
 */
export async function getDiscordBridgeInfo(): Promise<EdgeInfo | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/v1/edge/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'bridge',
        address: 'discord',
      }),
    });
    
    if (!response.ok) {
      return null;
    }
    
    return await response.json() as EdgeInfo;
  } catch (error) {
    console.error('Bridge lookup error:', error);
    return null;
  }
}
