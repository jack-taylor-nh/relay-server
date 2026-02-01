/**
 * Relay Crypto Utilities
 * 
 * Uses libsodium for all cryptographic operations:
 * - Ed25519 for signing
 * - X25519 for key exchange
 * - XChaCha20-Poly1305 for symmetric encryption
 */

// @ts-expect-error - libsodium-wrappers-sumo lacks complete type definitions
import sodium from 'libsodium-wrappers-sumo';
import type { KeyPair, EncryptedKeyBundle } from '../types';

let initialized = false;

/**
 * Initialize libsodium. Must be called before using any crypto functions.
 */
export async function initCrypto(): Promise<void> {
  if (initialized) return;
  await sodium.ready;
  initialized = true;
}

/**
 * Ensure crypto is initialized
 */
function ensureInit(): void {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
}

// ============================================
// Key Generation
// ============================================

/**
 * Generate a new Ed25519 signing keypair
 */
export function generateSigningKeyPair(): KeyPair {
  ensureInit();
  const kp = sodium.crypto_sign_keypair();
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}

/**
 * Derive X25519 encryption keypair from Ed25519 signing keypair
 */
export function deriveEncryptionKeyPair(signingKeyPair: KeyPair): KeyPair {
  ensureInit();
  return {
    publicKey: sodium.crypto_sign_ed25519_pk_to_curve25519(signingKeyPair.publicKey),
    privateKey: sodium.crypto_sign_ed25519_sk_to_curve25519(signingKeyPair.privateKey),
  };
}

/**
 * Compute fingerprint of a public key (first 16 bytes of SHA-256, hex encoded)
 */
export function computeFingerprint(publicKey: Uint8Array): string {
  ensureInit();
  const hash = sodium.crypto_generichash(32, publicKey);
  return sodium.to_hex(hash.slice(0, 16));
}

// ============================================
// Key Storage (Encryption at Rest)
// ============================================

const KEY_DERIVATION_ITERATIONS = 100000;
const KEY_DERIVATION_MEM_LIMIT = 67108864; // 64 MB
const KEY_DERIVATION_OPS_LIMIT = 3;

/**
 * Encrypt a private key for storage using a passphrase
 */
export function encryptPrivateKey(
  privateKey: Uint8Array,
  passphrase: string
): EncryptedKeyBundle {
  ensureInit();
  
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  
  // Derive encryption key from passphrase
  const key = sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    passphrase,
    salt,
    KEY_DERIVATION_OPS_LIMIT,
    KEY_DERIVATION_MEM_LIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  
  // Encrypt the private key
  const ciphertext = sodium.crypto_secretbox_easy(privateKey, nonce, key);
  
  // Zero out the derived key
  sodium.memzero(key);
  
  return {
    ciphertext,
    salt,
    nonce,
    iterations: KEY_DERIVATION_ITERATIONS,
    algorithm: 'xchacha20-poly1305',
  };
}

/**
 * Decrypt a private key from storage using a passphrase
 */
export function decryptPrivateKey(
  bundle: EncryptedKeyBundle,
  passphrase: string
): Uint8Array {
  ensureInit();
  
  // Derive encryption key from passphrase
  const key = sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    passphrase,
    bundle.salt,
    KEY_DERIVATION_OPS_LIMIT,
    KEY_DERIVATION_MEM_LIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  
  try {
    const privateKey = sodium.crypto_secretbox_open_easy(
      bundle.ciphertext,
      bundle.nonce,
      key
    );
    return privateKey;
  } finally {
    sodium.memzero(key);
  }
}

// ============================================
// Signing
// ============================================

/**
 * Sign a message with Ed25519 private key
 */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  ensureInit();
  return sodium.crypto_sign_detached(message, privateKey);
}

/**
 * Verify an Ed25519 signature
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  ensureInit();
  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Sign a string message (convenience wrapper)
 */
export function signString(message: string, privateKey: Uint8Array): string {
  ensureInit();
  const messageBytes = sodium.from_string(message);
  const signature = sign(messageBytes, privateKey);
  return sodium.to_base64(signature);
}

/**
 * Verify a string message signature (convenience wrapper)
 */
export function verifyString(
  message: string,
  signatureBase64: string,
  publicKey: Uint8Array
): boolean {
  ensureInit();
  const messageBytes = sodium.from_string(message);
  const signature = sodium.from_base64(signatureBase64);
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
  ensureInit();
  
  // Generate ephemeral keypair for this message
  const ephemeralKp = sodium.crypto_box_keypair();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  
  // Encrypt using crypto_box (X25519 + XSalsa20-Poly1305)
  const plaintextBytes = sodium.from_string(plaintext);
  const ciphertext = sodium.crypto_box_easy(
    plaintextBytes,
    nonce,
    recipientPubkey,
    ephemeralKp.privateKey
  );
  
  // Zero out ephemeral private key
  sodium.memzero(ephemeralKp.privateKey);
  
  return {
    ciphertext: sodium.to_base64(ciphertext),
    ephemeralPubkey: sodium.to_base64(ephemeralKp.publicKey),
    nonce: sodium.to_base64(nonce),
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
  ensureInit();
  
  const ciphertext = sodium.from_base64(ciphertextBase64);
  const nonce = sodium.from_base64(nonceBase64);
  const ephemeralPubkey = sodium.from_base64(ephemeralPubkeyBase64);
  
  const plaintext = sodium.crypto_box_open_easy(
    ciphertext,
    nonce,
    ephemeralPubkey,
    recipientPrivateKey
  );
  
  return sodium.to_string(plaintext);
}

// ============================================
// Utilities
// ============================================

/**
 * Generate a random nonce for authentication challenges
 */
export function generateNonce(): string {
  ensureInit();
  const bytes = sodium.randombytes_buf(32);
  return sodium.to_base64(bytes);
}

/**
 * Encode bytes to base64
 */
export function toBase64(bytes: Uint8Array): string {
  ensureInit();
  return sodium.to_base64(bytes);
}

/**
 * Decode base64 to bytes
 */
export function fromBase64(base64: string): Uint8Array {
  ensureInit();
  return sodium.from_base64(base64);
}

/**
 * Encode bytes to hex
 */
export function toHex(bytes: Uint8Array): string {
  ensureInit();
  return sodium.to_hex(bytes);
}

/**
 * Decode hex to bytes
 */
export function fromHex(hex: string): Uint8Array {
  ensureInit();
  return sodium.from_hex(hex);
}

/**
 * Generate a ULID-like ID (timestamp + random)
 */
export function generateId(): string {
  ensureInit();
  const timestamp = Date.now().toString(36).padStart(10, '0');
  const random = sodium.to_hex(sodium.randombytes_buf(8));
  return `${timestamp}${random}`;
}

/**
 * Securely zero memory
 */
export function secureZero(buffer: Uint8Array): void {
  ensureInit();
  sodium.memzero(buffer);
}
