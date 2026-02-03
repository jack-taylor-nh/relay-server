/**
 * Relay API Client
 * 
 * HTTP client for communicating with the Relay API server
 */

import { signPayload } from './crypto.js';

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
 * Look up edge by Relay handle (e.g., "@alice")
 * Used when Discord users message a Relay user by handle
 */
export async function lookupEdgeByHandle(handle: string): Promise<EdgeInfo | null> {
  try {
    // Handle lookup uses the 'native' type with handle as address
    const response = await fetch(`${API_BASE_URL}/v1/edge/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'native',
        address: handle.toLowerCase(),
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
}

/**
 * Forward encrypted Discord message to Relay API
 */
export async function forwardToApi(payload: {
  edgeId: string;
  senderHash: string;
  encryptedRecipientId: string;  // Encrypted Discord ID for reply routing (only worker can decrypt)
  encryptedPayload: string;
  receivedAt: string;
}): Promise<void> {
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
