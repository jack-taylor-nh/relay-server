/**
 * Generate X25519 encryption keypair for worker to decrypt recipient emails
 * 
 * Usage: node scripts/generate-worker-encryption-keypair.js
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const { encodeBase64 } = naclUtil;

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate X25519 encryption keypair
const keypair = nacl.box.keyPair();

console.log('\n=== Worker X25519 Encryption Keypair ===\n');
console.log('Private Key (hex - store in worker secrets as WORKER_ENCRYPTION_PRIVATE_KEY):');
console.log(bytesToHex(keypair.secretKey));
console.log('\nPublic Key (base64 - embed in client or expose via worker endpoint):');
console.log(encodeBase64(keypair.publicKey));
console.log('\nPublic Key (hex):');
console.log(bytesToHex(keypair.publicKey));
console.log('\n');
