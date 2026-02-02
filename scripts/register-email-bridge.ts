/**
 * Register Email Bridge Edge
 * 
 * This script creates a bridge edge record in the database for the email worker.
 * The bridge's X25519 public key is derived from the WORKER_ENCRYPTION_PRIVATE_KEY.
 * 
 * Usage:
 *   npx tsx scripts/register-email-bridge.ts <worker-public-key-base64>
 * 
 * Or fetch from worker:
 *   curl https://relay-email-worker.taylor-d-jack.workers.dev/public-key
 *   npx tsx scripts/register-email-bridge.ts <publicKey from response>
 */

import 'dotenv/config';  // Load .env file
import { db, edges } from '../src/db/index.js';
import { eq, and } from 'drizzle-orm';
import { ulid } from 'ulid';

const BRIDGE_ADDRESS = 'email';
const BRIDGE_ID = 'RELAY_EMAIL_BRIDGE';  // Well-known ID

async function registerEmailBridge(publicKeyBase64: string) {
  console.log('Registering email bridge edge...');
  console.log('  Address:', BRIDGE_ADDRESS);
  console.log('  Public Key:', publicKeyBase64.substring(0, 20) + '...');
  
  // Check if bridge already exists
  const existing = await db
    .select()
    .from(edges)
    .where(and(
      eq(edges.address, BRIDGE_ADDRESS),
      eq(edges.type, 'bridge')
    ))
    .limit(1);
  
  if (existing.length > 0) {
    console.log('\nBridge edge already exists:', existing[0].id);
    
    // Update the public key if different
    if (existing[0].x25519PublicKey !== publicKeyBase64) {
      console.log('Updating public key...');
      await db
        .update(edges)
        .set({ 
          x25519PublicKey: publicKeyBase64,
          updatedAt: new Date(),
        })
        .where(eq(edges.id, existing[0].id));
      console.log('Public key updated!');
    } else {
      console.log('Public key unchanged.');
    }
    
    return existing[0].id;
  }
  
  // Create new bridge edge
  const edgeId = BRIDGE_ID;
  
  await db.insert(edges).values({
    id: edgeId,
    identityId: null,  // Bridge edges don't belong to a user identity
    type: 'bridge',
    address: BRIDGE_ADDRESS,
    label: 'Email Bridge',
    status: 'active',
    securityLevel: 'gateway_secured',  // Bridges are gateway-secured by definition
    x25519PublicKey: publicKeyBase64,
    metadata: {
      displayName: 'Email Bridge',
      description: 'Cloudflare Email Worker for inbound/outbound email relay',
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  
  console.log('\n✅ Email bridge edge registered!');
  console.log('  Edge ID:', edgeId);
  console.log('\nClients can now resolve the bridge via:');
  console.log('  POST /v1/edge/resolve { type: "bridge", address: "email" }');
  
  return edgeId;
}

// Main
const publicKey = process.argv[2];

if (!publicKey) {
  console.log('Usage: node scripts/register-email-bridge.js <worker-public-key-base64>');
  console.log('\nTo get the worker public key:');
  console.log('  curl https://relay-email-worker.taylor-d-jack.workers.dev/public-key');
  process.exit(1);
}

registerEmailBridge(publicKey)
  .then(() => {
    console.log('\nDone!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Error:', error);
    process.exit(1);
  });
