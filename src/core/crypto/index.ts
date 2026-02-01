/**
 * Relay Crypto Utilities
 * 
 * Uses tweetnacl for all cryptographic operations:
 * - Ed25519 for signing
 * - X25519 for key exchange
 * - XSalsa20-Poly1305 for symmetric encryption
 */

import nacl from 'tweetnacl';
import type { KeyPair, EncryptedKeyBundle } from '../types/index.js';

// ============================================
// Key Generation
// ============================================

/**
 * Generate a new Ed25519 signing keypair
 */
export function generateSigningKeyPair(): KeyPair {
  const kp = nacl.sign.keyPair();
  return {
    publicKey: kp.publicKey,
    privateKey: kp.secretKey,
  };
}

/**
 * Derive X25519 encryption keypair from Ed25519 signing keypair
 */
export function deriveEncryptionKeyPair(signingKeyPair: KeyPair): KeyPair {
  return {
    publicKey: nacl.box.keyPair.fromSecretKey(
      signingKeyPair.privateKey.subarray(0, 32)
    ).publicKey,
    privateKey: signingKeyPair.privateKey.subarray(0, 32),
  };
}

/**
 * Compute fingerprint of a public key (first 16 bytes of hash, hex encoded)
 */
export function computeFingerprint(publicKey: Uint8Array): string {
  const hash = nacl.hash(publicKey);
  return Buffer.from(hash.slice(0, 16)).toString('hex');
}


// ============================================
// Key Storage (Encryption at Rest)
// ============================================

/**
 * Encrypt a private key for storage using a passphrase
 * Note: tweetnacl doesn't have password hashing, this is a simplified version
 */
export function encryptPrivateKey(
  privateKey: Uint8Array,
  passphrase: string
): EncryptedKeyBundle {
  // Simplified: use first 32 bytes of passphrase hash as key
  const passphraseHash = nacl.hash(Buffer.from(passphrase, 'utf-8'));
  const key = passphraseHash.slice(0, nacl.secretbox.keyLength);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const salt = nacl.randomBytes(16);
  
  const ciphertext = nacl.secretbox(privateKey, nonce, key);
  
  return {
    ciphertext,
    salt,
    nonce,
    iterations: 1,
    algorithm: 'xsalsa20-poly1305',
  };
}

/**
 * Decrypt a private key from storage using a passphrase
 */
export function decryptPrivateKey(
  bundle: EncryptedKeyBundle,
  passphrase: string
): Uint8Array {
  const passphraseHash = nacl.hash(Buffer.from(passphrase, 'utf-8'));
  const key = passphraseHash.slice(0, nacl.secretbox.keyLength);
  
  const privateKey = nacl.secretbox.open(bundle.ciphertext, bundle.nonce, key);
  
  if (!privateKey) {
    throw new Error('Failed to decrypt private key');
  }
  
  return privateKey;
}

// ============================================
// Signing
// ============================================

/**
 * Sign a message with Ed25519 private key
 */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, privateKey);
}

/**
 * Verify an Ed25519 signature
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return nacl.sign.detached.verify(message, signature, publicKey);
}

/**
 * Sign a string message (convenience wrapper)
 */
export function signString(message: string, privateKey: Uint8Array): string {
  const messageBytes = Buffer.from(message, 'utf-8');
  const signature = sign(messageBytes, privateKey);
  return Buffer.from(signature).toString('base64');
}

/**
 * Verify a string message signature (convenience wrapper)
 */
export function verifyString(
  message: string,
  signatureBase64: string,
  publicKey: Uint8Array
): boolean {
  const messageBytes = Buffer.from(message, 'utf-8');
  const signature = Buffer.from(signatureBase64, 'base64');
  return verify(messageBytes, signature, publicKey);
}

// ============================================
// Encryption (for Native Chat)
// ============================================

/**
 * Encrypt a message for a recipient using their X25519 public key
 * Uses ephemeral key exchange for forward secrecy per-message
 */
export function encryptMessage(
  plaintext: string,
  recipientPubkey: Uint8Array,
  _senderPrivateKey: Uint8Array
): { ciphertext: string; ephemeralPubkey: string; nonce: string } {
  // Generate ephemeral keypair for this message
  const ephemeralKp = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  
  // Encrypt using crypto_box
  const plaintextBytes = Buffer.from(plaintext, 'utf-8');
  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    recipientPubkey,
    ephemeralKp.secretKey
  );
  
  return {
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    ephemeralPubkey: Buffer.from(ephemeralKp.publicKey).toString('base64'),
    nonce: Buffer.from(nonce).toString('base64'),
  };
}

/**
 * Decrypt a message using the recipient's X25519 private key
 */
export function decryptMessage(
  ciphertextBase64: string,
  nonceBase64: string,
  ephemeralPubkeyBase64: string,
  recipientPrivateKey: Uint8Array
): string {
  const ciphertext = Buffer.from(ciphertextBase64, 'base64');
  const nonce = Buffer.from(nonceBase64, 'base64');
  const ephemeralPubkey = Buffer.from(ephemeralPubkeyBase64, 'base64');
  
  const plaintext = nacl.box.open(
    ciphertext,
    nonce,
    ephemeralPubkey,
    recipientPrivateKey
  );
  
  if (!plaintext) {
    throw new Error('Failed to decrypt message');
  }
  
  return Buffer.from(plaintext).toString('utf-8');
}

// ============================================
// Utilities
// ============================================

/**
 * Generate a random nonce for authentication challenges
 */
export function generateNonce(): string {
  const bytes = nacl.randomBytes(32);
  return Buffer.from(bytes).toString('base64');
}

/**
 * Encode bytes to base64
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Decode base64 to bytes
 */
export function fromBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Encode bytes to hex
 */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Decode hex to bytes
 */
export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Generate a ULID-like ID (timestamp + random)
 */
export function generateId(): string {
  const timestamp = Date.now().toString(36).padStart(10, '0');
  const random = Buffer.from(nacl.randomBytes(8)).toString('hex');
  return `${timestamp}${random}`;
}

/**
 * Securely zero memory (noop for tweetnacl - no memzero equivalent)
 */
export function secureZero(buffer: Uint8Array): void {
  // tweetnacl doesn't have memzero, just overwrite with zeros
  buffer.fill(0);
}
