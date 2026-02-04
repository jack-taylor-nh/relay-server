#!/usr/bin/env node

/**
 * Generate encryption keys for webhook worker
 * 
 * Generates:
 * - X25519 keypair for encrypting webhook payloads
 * - Ed25519 keypair for signing requests to API
 */

import nacl from 'tweetnacl';

// Generate X25519 keypair for encryption
const encryptionKeypair = nacl.box.keyPair();
const encryptionPrivateKeyHex = Buffer.from(encryptionKeypair.secretKey).toString('hex');
const encryptionPublicKeyHex = Buffer.from(encryptionKeypair.publicKey).toString('hex');

// Generate Ed25519 keypair for signing
const signingKeypair = nacl.sign.keyPair();
const signingPrivateKeyHex = Buffer.from(signingKeypair.secretKey).toString('hex');
const signingPublicKeyHex = Buffer.from(signingKeypair.publicKey).toString('hex');

console.log('='.repeat(80));
console.log('Relay Webhook Worker - Encryption Keys Generated');
console.log('='.repeat(80));
console.log('');
console.log('📋 Copy these to your Railway environment variables:');
console.log('');
console.log('WORKER_ENCRYPTION_PRIVATE_KEY=' + encryptionPrivateKeyHex);
console.log('');
console.log('WORKER_PRIVATE_KEY=' + signingPrivateKeyHex);
console.log('');
console.log('='.repeat(80));
console.log('');
console.log('📝 Public keys (for reference/verification):');
console.log('');
console.log('X25519 Public Key (encryption): ' + encryptionPublicKeyHex);
console.log('Ed25519 Public Key (signing):   ' + signingPublicKeyHex);
console.log('');
console.log('='.repeat(80));
console.log('');
console.log('⚠️  IMPORTANT: Keep private keys secret! Do NOT commit to version control.');
console.log('');
