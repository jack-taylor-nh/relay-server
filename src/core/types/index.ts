/**
 * Relay Protocol Types
 */

// ============================================
// Identity & Handles
// ============================================

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedKeyBundle {
  /** Encrypted private key blob */
  ciphertext: Uint8Array;
  /** Salt used for key derivation */
  salt: Uint8Array;
  /** Nonce used for encryption */
  nonce: Uint8Array;
  /** Key derivation iterations */
  iterations: number;
  /** Algorithm identifier for future-proofing */
  algorithm: 'xchacha20-poly1305';
}

export interface Identity {
  /** Unique identifier (pubkey fingerprint) */
  id: string;
  /** Ed25519 public key (base64) */
  publicKey: string;
  /** Handle (without & prefix) */
  handle: string | null;
  /** When this identity was created */
  createdAt: string;
}

export interface Handle {
  /** Handle string (without & prefix) */
  name: string;
  /** Public key fingerprint */
  pubkeyFingerprint: string;
  /** When handle was claimed */
  claimedAt: string;
}

// ============================================
// Conversations & Messages
// ============================================

export type ConversationType = 'native' | 'email' | 'contact_endpoint';

export interface Conversation {
  /** Unique conversation ID (ulid) */
  id: string;
  /** Type of conversation */
  type: ConversationType;
  /** Participants (pubkey fingerprints for native, hashed identifiers for email) */
  participants: string[];
  /** Display name for the counterparty */
  counterpartyName: string | null;
  /** Last message preview (plaintext, client-side only) */
  lastMessagePreview?: string;
  /** Last activity timestamp */
  lastActivityAt: string;
  /** When conversation was created */
  createdAt: string;
  /** Unread message count (client-side) */
  unreadCount?: number;
}

export interface Message {
  /** Unique message ID (ulid) */
  id: string;
  /** Conversation this belongs to */
  conversationId: string;
  /** Sender pubkey fingerprint */
  senderFingerprint: string;
  /** For native: encrypted content (base64) */
  ciphertext?: string;
  /** For email: the message is stored differently */
  emailContent?: EmailMessageContent;
  /** Signature over message envelope (base64) */
  signature: string;
  /** When message was created */
  createdAt: string;
  /** Message status */
  status: MessageStatus;
}

export type MessageStatus = 'sending' | 'sent' | 'delivered' | 'failed';

export interface EmailMessageContent {
  /** Original sender email (hashed for storage, decrypted for display) */
  fromAddress: string;
  /** Subject line */
  subject: string;
  /** Plain text body */
  textBody: string;
  /** HTML body (sanitized) */
  htmlBody?: string;
  /** Whether remote images are blocked */
  remoteImagesBlocked: boolean;
}

// ============================================
// Email Aliases
// ============================================

export interface EmailAlias {
  /** Unique alias ID */
  id: string;
  /** The alias address (e.g., a8f3k2@relay.sh) */
  address: string;
  /** User-provided label */
  label: string | null;
  /** Whether alias is active */
  isActive: boolean;
  /** When alias was created */
  createdAt: string;
  /** Message count through this alias */
  messageCount: number;
}

// ============================================
// API Request/Response Types
// ============================================

// Auth
export interface NonceRequest {
  pubkeyFingerprint: string;
}

export interface NonceResponse {
  nonce: string;
  expiresAt: string;
}

export interface AuthVerifyRequest {
  pubkeyFingerprint: string;
  nonce: string;
  signature: string;
}

export interface AuthVerifyResponse {
  token: string;
  expiresAt: string;
}

// Handles
export interface HandleClaimRequest {
  handle: string;
  publicKey: string;
  nonce: string;
  signature: string;
}

export interface HandleResolveResponse {
  handle: string;
  publicKey: string;
  claimedAt: string;
}

// Conversations
export interface ConversationsListResponse {
  conversations: Conversation[];
  cursor: string | null;
}

export interface MessagesListResponse {
  messages: Message[];
  cursor: string | null;
}

export interface SendMessageRequest {
  ciphertext: string;
  signature: string;
  recipientFingerprint: string;
}

// Email Aliases
export interface CreateAliasRequest {
  label?: string;
  /** If true, generate random alias. If false, use provided name */
  random: boolean;
  /** Only used if random is false */
  name?: string;
}

export interface CreateAliasResponse {
  alias: EmailAlias;
}

// ============================================
// Encrypted Message Envelope (Native Chat)
// ============================================

export interface MessageEnvelope {
  /** Message ID (ulid) */
  id: string;
  /** Conversation ID */
  conversationId: string;
  /** Sender pubkey fingerprint */
  senderFingerprint: string;
  /** Recipient pubkey fingerprint */
  recipientFingerprint: string;
  /** Unix timestamp (ms) */
  timestamp: number;
  /** Encrypted content (base64) */
  ciphertext: string;
  /** Ephemeral public key for key exchange (base64) */
  ephemeralPubkey: string;
  /** Nonce used for encryption (base64) */
  nonce: string;
}

// ============================================
// Error Types
// ============================================

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export const ErrorCodes = {
  // Auth
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  NONCE_EXPIRED: 'NONCE_EXPIRED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  
  // Handles
  HANDLE_TAKEN: 'HANDLE_TAKEN',
  HANDLE_INVALID: 'HANDLE_INVALID',
  HANDLE_RESERVED: 'HANDLE_RESERVED',
  HANDLE_NOT_FOUND: 'HANDLE_NOT_FOUND',
  
  // Rate limiting
  RATE_LIMITED: 'RATE_LIMITED',
  
  // General
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;
