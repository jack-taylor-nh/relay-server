/**
 * Generate X25519 and Ed25519 keypairs for Discord Worker
 * 
 * Run with: npm run generate-keypair
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const { encodeBase64 } = naclUtil;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

console.log('🔐 Generating Discord Worker Keypairs\n');

// Generate X25519 keypair for encryption
const encryptionKeypair = nacl.box.keyPair();
console.log('=== X25519 Encryption Keypair ===');
console.log('Private Key (hex - keep secret!):');
console.log(`  WORKER_ENCRYPTION_PRIVATE_KEY=${bytesToHex(encryptionKeypair.secretKey)}`);
console.log('\nPublic Key (base64 - share with clients):');
console.log(`  ${encodeBase64(encryptionKeypair.publicKey)}`);

// Generate Ed25519 keypair for signing
const signingKeypair = nacl.sign.keyPair();
console.log('\n=== Ed25519 Signing Keypair ===');
console.log('Private Key (hex - keep secret!):');
console.log(`  WORKER_SIGNING_PRIVATE_KEY=${bytesToHex(signingKeypair.secretKey)}`);
console.log('\nPublic Key (base64 - for verification):');
console.log(`  ${encodeBase64(signingKeypair.publicKey)}`);

console.log('\n✅ Add the private keys to your .env file');
console.log('✅ Use the X25519 public key when registering the bridge:');
console.log(`   npx tsx scripts/register-discord-bridge.ts ${encodeBase64(encryptionKeypair.publicKey)}`);
