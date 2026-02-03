/**
 * Register Discord Bridge Edge
 * 
 * This script creates a bridge edge record in the database for the Discord bot.
 * The bridge's X25519 public key is derived from the WORKER_ENCRYPTION_PRIVATE_KEY.
 * 
 * Usage:
 *   npx tsx scripts/register-discord-bridge.ts <worker-public-key-base64>
 * 
 * Or generate keypair first:
 *   cd discord-worker && npm run generate-keypair
 *   npx tsx scripts/register-discord-bridge.ts <publicKey from output>
 */

import 'dotenv/config';
import { db, edges } from '../src/db/index.js';
import { eq, and } from 'drizzle-orm';

const BRIDGE_ADDRESS = 'discord';
const BRIDGE_ID = 'RELAY_DISCORD_BRIDGE';

async function registerDiscordBridge(publicKeyBase64: string) {
  console.log('Registering Discord bridge edge...');
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
    label: 'Discord Bridge',
    status: 'active',
    securityLevel: 'gateway_secured',
    x25519PublicKey: publicKeyBase64,
    metadata: {
      displayName: 'Discord Bridge',
      description: 'Discord bot for bidirectional DM relay',
      workerUrl: process.env.DISCORD_WORKER_URL || 'https://relay-discord-worker.up.railway.app',
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  
  console.log('\n✅ Discord bridge edge registered!');
  console.log('  Edge ID:', edgeId);
  console.log('\nClients can now resolve the bridge via:');
  console.log('  POST /v1/edge/resolve { type: "bridge", address: "discord" }');
  
  return edgeId;
}

// Main
const publicKey = process.argv[2];

if (!publicKey) {
  console.log('Usage: npx tsx scripts/register-discord-bridge.ts <worker-public-key-base64>');
  console.log('\nTo generate a keypair:');
  console.log('  cd discord-worker && npm run generate-keypair');
  process.exit(1);
}

registerDiscordBridge(publicKey)
  .then(() => {
    console.log('\nDone!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Error:', error);
    process.exit(1);
  });
