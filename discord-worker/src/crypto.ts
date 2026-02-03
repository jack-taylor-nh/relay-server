/**
 * Cryptographic utilities for Discord Worker
 * 
 * Mirrors email-worker crypto patterns:
 * - X25519 for encryption/decryption
 * - Ed25519 for signing
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const { encodeBase64, decodeBase64 } = naclUtil;

/**
 * Get worker's X25519 public key (for clients to encrypt recipient IDs)
 */
export function getWorkerPublicKey(): string {
  const privateKeyHex = process.env.WORKER_ENCRYPTION_PRIVATE_KEY!;
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const keypair = nacl.box.keyPair.fromSecretKey(privateKeyBytes);
  return encodeBase64(keypair.publicKey);
}

/**
 * Encrypt message payload with recipient's edge X25519 public key
 * Used for zero-knowledge forwarding to Relay API
 */
export function encryptPayload(payload: object, recipientPublicKeyBase64: string): string {
  const recipientPublicKey = decodeBase64(recipientPublicKeyBase64);
  
  // Generate ephemeral keypair
  const ephemeralKeyPair = nacl.box.keyPair();
  
  // Serialize payload
  const messageBytes = new TextEncoder().encode(JSON.stringify(payload));
  
  // Generate nonce
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  
  // Encrypt with box (authenticated encryption)
  const encrypted = nacl.box(
    messageBytes,
    nonce,
    recipientPublicKey,
    ephemeralKeyPair.secretKey
  );
  
  // Package as JSON: ephemeralPubkey, nonce, ciphertext (all base64)
  return JSON.stringify({
    ephemeralPubkey: encodeBase64(ephemeralKeyPair.publicKey),
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(encrypted),
  });
}

/**
 * Decrypt data encrypted for worker's X25519 public key
 * Used for decrypting recipient Discord IDs from Relay clients
 * 
 * Expected format: base64(ephemeralPubkey):base64(nonce):base64(ciphertext)
 */
export function decryptForWorker(encryptedPackage: string): string {
  const privateKeyHex = process.env.WORKER_ENCRYPTION_PRIVATE_KEY!;
  
  // Handle both : separated and JSON formats
  let ephemeralPubkey: Uint8Array;
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  
  if (encryptedPackage.startsWith('{')) {
    // JSON format
    const pkg = JSON.parse(encryptedPackage);
    ephemeralPubkey = decodeBase64(pkg.ephemeralPubkey);
    nonce = decodeBase64(pkg.nonce);
    ciphertext = decodeBase64(pkg.ciphertext);
  } else {
    // Colon-separated format
    const parts = encryptedPackage.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted package format');
    }
    ephemeralPubkey = decodeBase64(parts[0]);
    nonce = decodeBase64(parts[1]);
    ciphertext = decodeBase64(parts[2]);
  }
  
  // Derive worker's keypair from private key
  const workerPrivateKey = hexToBytes(privateKeyHex);
  const workerKeypair = nacl.box.keyPair.fromSecretKey(workerPrivateKey);
  
  // Decrypt
  const decrypted = nacl.box.open(
    ciphertext,
    nonce,
    ephemeralPubkey,
    workerKeypair.secretKey
  );
  
  if (!decrypted) {
    throw new Error('Decryption failed - invalid ciphertext or key');
  }
  
  return new TextDecoder().decode(decrypted);
}

/**
 * Sign payload with worker's Ed25519 private key
 */
export function signPayload(message: string): string {
  const privateKeyHex = process.env.WORKER_SIGNING_PRIVATE_KEY;
  if (!privateKeyHex) {
    throw new Error('WORKER_SIGNING_PRIVATE_KEY not configured');
  }
  
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
  return encodeBase64(signature);
}

/**
 * Hash a Discord user ID for privacy (deterministic for conversation matching)
 */
export async function hashDiscordId(discordId: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(discordId.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encrypt data for worker storage (worker can decrypt later for reply routing)
 * Uses worker's own X25519 key - only the worker can decrypt this
 * 
 * Returns: base64(ephemeralPubkey):base64(nonce):base64(ciphertext)
 */
export function encryptForWorkerStorage(data: string): string {
  const privateKeyHex = process.env.WORKER_ENCRYPTION_PRIVATE_KEY!;
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const workerKeypair = nacl.box.keyPair.fromSecretKey(privateKeyBytes);
  
  // Generate ephemeral keypair for this encryption
  const ephemeralKeyPair = nacl.box.keyPair();
  
  // Serialize data
  const messageBytes = new TextEncoder().encode(data);
  
  // Generate nonce
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  
  // Encrypt with box (to worker's public key, from ephemeral private key)
  const encrypted = nacl.box(
    messageBytes,
    nonce,
    workerKeypair.publicKey,
    ephemeralKeyPair.secretKey
  );
  
  // Return as colon-separated base64
  return `${encodeBase64(ephemeralKeyPair.publicKey)}:${encodeBase64(nonce)}:${encodeBase64(encrypted)}`;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
