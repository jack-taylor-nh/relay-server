/**
 * Generate Ed25519 keypair for worker authentication
 * 
 * Run: node generate-worker-keypair.js
 */

import nacl from 'tweetnacl';

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate Ed25519 keypair
const keypair = nacl.sign.keyPair();

const privateKeyHex = bytesToHex(keypair.secretKey);
const publicKeyHex = bytesToHex(keypair.publicKey);

console.log('\n=== Worker Authentication Keypair ===\n');
console.log('Add these to your secrets/environment variables:\n');
console.log('WORKER_PRIVATE_KEY (worker secret):');
console.log(privateKeyHex);
console.log('\nWORKER_PUBLIC_KEY (server environment):');
console.log(publicKeyHex);
console.log('\n=== Setup Commands ===\n');
console.log('# Set worker private key:');
console.log(`cd relay-server/email-worker`);
console.log(`echo "${privateKeyHex}" | npx wrangler secret put WORKER_PRIVATE_KEY`);
console.log('\n# Set server public key (Railway):');
console.log(`# Add to Railway environment variables:`);
console.log(`WORKER_PUBLIC_KEY=${publicKeyHex}`);
console.log('\n=== Security Notes ===\n');
console.log('- Private key: Keep secret, only in worker');
console.log('- Public key: Can be in server environment');
console.log('- Purpose: Worker signs payloads, server verifies signatures');
console.log('- Prevents: Malicious worker injection attacks');
console.log('');
