#!/usr/bin/env node

/**
 * Verify and display public key from private key
 * 
 * Usage: npx ts-node scripts/verify-keypair.ts <private-key-hex>
 * 
 * Handles both:
 * - 32-byte seeds (64 hex chars)
 * - 64-byte full secret keys (128 hex chars)
 */

import nacl from 'tweetnacl';

const privateKeyHex = process.argv[2];

if (!privateKeyHex) {
  console.log('Usage: npx ts-node scripts/verify-keypair.ts <private-key-hex>');
  console.log('');
  console.log('Pass your WORKER_PRIVATE_KEY value to see the corresponding public key.');
  process.exit(1);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

const privateKeyBytes = hexToBytes(privateKeyHex);

console.log('');
console.log('='.repeat(80));
console.log('Private key length:', privateKeyBytes.length, 'bytes');
console.log('');

let publicKey: Uint8Array;

if (privateKeyBytes.length === 32) {
  // It's a seed - derive keypair
  console.log('Key type: 32-byte SEED');
  const keypair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
  publicKey = keypair.publicKey;
  console.log('');
  console.log('Derived full secret key (128 hex chars):');
  console.log(Buffer.from(keypair.secretKey).toString('hex'));
} else if (privateKeyBytes.length === 64) {
  // It's a full secret key - extract public key (last 32 bytes)
  console.log('Key type: 64-byte FULL SECRET KEY');
  publicKey = privateKeyBytes.slice(32);
} else {
  console.error('Invalid key length! Expected 32 or 64 bytes, got', privateKeyBytes.length);
  process.exit(1);
}

console.log('');
console.log('='.repeat(80));
console.log('WORKER_PUBLIC_KEY (set this on the server):');
console.log('');
console.log(Buffer.from(publicKey).toString('hex'));
console.log('');
console.log('='.repeat(80));
