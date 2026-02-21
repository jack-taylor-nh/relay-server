/**
 * Relay API - Database Schema
 * 
 * PostgreSQL schema using Drizzle ORM
 * 
 * Core Architecture:
 * - Identity: Cryptographic anchor, stable and long-lived
 * - Handle: Optional friendly name(s) attached to identity (disposable)
 * - Edge: Contact surfaces (email, links, bridges) - all disposable
 * - Conversation: Communication threads, track their source edge
 */

import { pgTable, text, timestamp, boolean, integer, index, uniqueIndex, jsonb } from 'drizzle-orm/pg-core';

// ============================================
// Identities (Core Anchor)
// ============================================

export const identities = pgTable('identities', {
  /** Identity ID = pubkey fingerprint (hex, 32 chars) */
  id: text('id').primaryKey(),
  /** Public key (base64 encoded) */
  publicKey: text('public_key').notNull(),
  /** Home server domain (e.g., "userelay.org") */
  homeServer: text('home_server').notNull().default('userelay.org'),
  /** Account status: active | locked | hidden */
  status: text('status').notNull().$type<'active' | 'locked' | 'hidden'>().default('active'),
  /** When identity was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  /** Last activity timestamp */
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
});

// ============================================
// Handles - REMOVED (v0.0.8)
// ============================================
// Handles are now represented as native edges with:
// - type: 'native'
// - address: handle name (e.g., 'alice')
// - ownerQueryKey: HMAC(identityId, secret) for ownership
// 
// This provides:
// - No identity_id column exposing ownership
// - Unified edge-based architecture
// - Handles are burnable like any edge
// - Same first-contact policies as other edges

// ============================================
// Edges (Contact Points - Unified Model)
// ============================================

export type EdgeType = 
  | 'native'        // Direct Relay-to-Relay (implicit)
  | 'email'         // Email alias @rlymsg.com
  | 'contact_link'  // Public contact form
  | 'bridge'        // System bridge (email worker, discord bot, etc.)
  | 'discord'       // Discord bridge
  | 'webhook'       // Webhook receiver
  | 'local-llm'     // Local LLM bridge edge
  | 'sms'           // SMS bridge
  | 'github'        // GitHub bridge
  | 'slack'         // Slack bridge
  | 'other';        // Other platforms

export type EdgeStatus = 'active' | 'disabled' | 'rotated' | 'burned';

export type SecurityLevel = 'e2ee' | 'gateway_secured';

export type ConversationSecurityLevel = SecurityLevel | 'mixed';

export type FirstContactMode = 'open' | 'pow' | 'allowlist' | 'mutual';

export type EdgePolicy = {
  rateLimit?: number;
  firstContact?: {
    mode: FirstContactMode;
    powDifficulty?: number;
    allowlist?: string[];
  };
  denylist?: string[];
};

export const edges = pgTable('edges', {
  /** Unique edge ID (ulid) */
  id: text('id').primaryKey(),
  
  /** Zero-knowledge owner query key: HMAC-SHA256(identityId, SERVER_SECRET_SALT)
   * Used for filtering user's edges without revealing identity
   * NULL when edge is burned (makes it unlinkable)
   */
  ownerQueryKey: text('owner_query_key'),
  
  /** Bridge type: email, native, discord, telegram, sms, etc. */
  bridgeType: text('bridge_type').notNull().default('email'),
  /** True for native Relay-to-Relay edges */
  isNative: boolean('is_native').default(false).notNull(),
  /** Bridge-specific metadata (credentials, config) as encrypted JSON */
  metadata: jsonb('metadata').default({}).notNull(),
  /** Edge type */
  type: text('type').notNull().$type<EdgeType>(),
  /** Address/identifier (email address, link slug, platform ID) */
  address: text('address').notNull(),
  /** User-friendly label */
  label: text('label'),
  /** Edge status */
  status: text('status').notNull().$type<EdgeStatus>().default('active'),
  /** Security level for conversations through this edge */
  securityLevel: text('security_level').notNull().$type<SecurityLevel>(),
  /** X25519 encryption public key (for email encryption, derived from Ed25519 signing key) */
  x25519PublicKey: text('x25519_public_key'),
  /** When edge was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  /** When edge was disabled (if applicable) */
  disabledAt: timestamp('disabled_at', { withTimezone: true }),
  /** If rotated, the edge this was rotated from */
  rotatedFromEdgeId: text('rotated_from_edge_id'),
  /** Policy rules (rate limits, first contact, deny lists) */
  policy: jsonb('policy').$type<EdgePolicy>(),
  /** Message count through this edge */
  messageCount: integer('message_count').default(0).notNull(),
  /** Last activity timestamp */
  lastActivityAt: timestamp('last_activity_at', { withTimezone: true }),
}, (table) => ({
  ownerQueryKeyIdx: index('edges_owner_query_key_idx').on(table.ownerQueryKey),
  // Unique per (type, address) - allows same handle across different edge types
  typeAddressIdx: uniqueIndex('edges_type_address_idx').on(table.type, table.address),
  typeIdx: index('edges_type_idx').on(table.type),
  bridgeTypeIdx: index('edges_bridge_type_idx').on(table.bridgeType),
  isNativeIdx: index('edges_is_native_idx').on(table.isNative),
}));

// ============================================
// Auth Nonces (short-lived)
// ============================================

export const authNonces = pgTable('auth_nonces', {
  /** Nonce value */
  nonce: text('nonce').primaryKey(),
  /** Identity ID this nonce is for */
  identityId: text('identity_id').references(() => identities.id).notNull(),
  /** When nonce expires */
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  /** When nonce was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================
// Conversations
// ============================================

export type ConversationOrigin = EdgeType;

export const conversations = pgTable('conversations', {
  /** Unique conversation ID (ulid) */
  id: text('id').primaryKey(),
  /** Origin type (matches edge type) */
  origin: text('origin').notNull().$type<ConversationOrigin>(),
  /** Edge ID this conversation came through (null for native/direct) */
  edgeId: text('edge_id').references(() => edges.id),
  /** Security level: e2ee, gateway_secured, or mixed (per-message varies) */
  securityLevel: text('security_level').notNull().$type<ConversationSecurityLevel>(),
  /** Encrypted counterparty metadata (NaCl box for edge's X25519 key)
   * Contains: { counterpartyDisplayName: string, counterpartyPlatformId?: string }
   * Only the client can decrypt this - server stores opaque blob
   * For native conversations: counterparty.handle is resolved from participants */
  encryptedMetadata: text('encrypted_metadata'),
  /** Bridge-specific metadata (JSONB) - NOT encrypted, for worker use
   * For Discord: { conversationMessageId: string } - the bot's DM message ID for editing
   * For Email: { threadId?: string } - email thread references */
  bridgeMetadata: jsonb('bridge_metadata'),
  /** Double Ratchet state for E2EE conversations (JSONB) */
  ratchetState: jsonb('ratchet_state'),
  /** When conversation was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  /** Last activity timestamp (for sorting) */
  lastActivityAt: timestamp('last_activity_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  edgeIdx: index('conversations_edge_idx').on(table.edgeId),
  originIdx: index('conversations_origin_idx').on(table.origin),
}));

// ============================================
// Conversation Participants
// ============================================

export const conversationParticipants = pgTable('conversation_participants', {
  /** Conversation ID */
  conversationId: text('conversation_id').references(() => conversations.id).notNull(),
  /** Edge ID this participant is using in this conversation */
  edgeId: text('edge_id').references(() => edges.id),
  /** For external contacts: external identifier (hashed email, etc.) */
  externalId: text('external_id'),
  /** Display name (for external counterparties) */
  displayName: text('display_name'),
  /** Whether this is the conversation owner */
  isOwner: boolean('is_owner').default(false).notNull(),
  /** When participant joined */
  joinedAt: timestamp('joined_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  convIdx: index('conv_participants_conv_idx').on(table.conversationId),
  edgeIdx: index('conv_participants_edge_idx').on(table.edgeId),
  externalIdx: index('conv_participants_external_idx').on(table.externalId),
}));

// ============================================
// Messages
// ============================================

export const messages = pgTable('messages', {
  /** Unique message ID (ulid) */
  id: text('id').primaryKey(),
  /** Protocol version (e.g., "1.0") */
  protocolVersion: text('protocol_version').notNull().default('1.0'),
  /** Conversation this belongs to */
  conversationId: text('conversation_id').references(() => conversations.id).notNull(),
  /** Edge ID this message came through */
  edgeId: text('edge_id').references(() => edges.id),
  /** Origin type (edge type) */
  origin: text('origin').$type<EdgeType>(),
  /** Security level for this specific message */
  securityLevel: text('security_level').notNull().$type<SecurityLevel>().default('e2ee'),
  /** Content type (MIME-like, e.g., "text/plain", "text/markdown", "application/encrypted") */
  contentType: text('content_type').notNull().default('text/plain'),
  /** Sender: external ID for non-Relay contacts */
  senderExternalId: text('sender_external_id'),
  /** For e2ee: encrypted content (base64) */
  ciphertext: text('ciphertext'),
  /** Ephemeral/DH public key for decryption (base64) - for ratchet, this is the dh key */
  ephemeralPubkey: text('ephemeral_pubkey'),
  /** Nonce used for encryption (base64) */
  nonce: text('nonce'),
  /** Double Ratchet: Previous chain length */
  ratchetPn: integer('ratchet_pn'),
  /** Double Ratchet: Message number in current chain */
  ratchetN: integer('ratchet_n'),
  /** For gateway_secured: encrypted package from worker (zero-knowledge) */
  encryptedContent: text('encrypted_content'),
  /** For gateway_secured: plaintext content (server-readable) - DEPRECATED */
  plaintextContent: text('plaintext_content'),
  /** Signature over message envelope (base64) - for e2ee */
  signature: text('signature'),
  /** When message was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  convIdx: index('messages_conv_idx').on(table.conversationId),
  createdIdx: index('messages_created_idx').on(table.createdAt),
}));

// Note: emailAliases table removed - edges table now handles all contact surfaces

// ============================================
// Bridge Messages (unified metadata for all bridge origins)
// ============================================

/**
 * Platform-specific metadata structures for bridge messages
 */
export type EmailBridgeMetadata = {
  fromAddressHash: string;  // Hashed email for privacy
  subject?: string;
  emailMessageId?: string;  // Message-ID header for threading
  inReplyTo?: string;       // In-Reply-To header
};

export type DiscordBridgeMetadata = {
  // Encrypted Discord user ID - only the discord worker can decrypt this for replies
  // This ensures zero-knowledge: the server never sees the actual Discord user ID
  encryptedDiscordId: string;
  discordMessageId?: string;
  // The bot's conversation message ID - this is the message we edit to append replies
  conversationMessageId?: string;
};

export type SlackBridgeMetadata = {
  slackUserId: string;
  slackTeamId: string;
  channelId?: string;
  threadTs?: string;
};

// Union type for all bridge metadata
export type BridgeMetadata = 
  | EmailBridgeMetadata 
  | DiscordBridgeMetadata 
  | SlackBridgeMetadata
  | Record<string, unknown>; // Extensible for future bridges

export const bridgeMessages = pgTable('bridge_messages', {
  /** References the message ID */
  messageId: text('message_id').references(() => messages.id).primaryKey(),
  /** Bridge type: email, discord, slack, sms, etc. */
  bridgeType: text('bridge_type').notNull().$type<EdgeType>(),
  /** External sender identifier (hashed email, discord user ID, etc.) - used for conversation matching */
  senderExternalId: text('sender_external_id').notNull(),
  /** Display name from the external platform */
  senderDisplayName: text('sender_display_name'),
  /** Message ID on the external platform (for threading, deduplication) */
  platformMessageId: text('platform_message_id'),
  /** Platform-specific metadata (JSONB for flexibility) */
  metadata: jsonb('metadata').$type<BridgeMetadata>(),
}, (table) => ({
  bridgeTypeIdx: index('bridge_messages_bridge_type_idx').on(table.bridgeType),
  senderIdx: index('bridge_messages_sender_idx').on(table.senderExternalId),
}));

// ============================================
// REMOVED: Email Messages table (migrated to bridge_messages)
// Dropped in migration 0011_add_encrypted_metadata_drop_deprecated.sql
// ============================================

// ============================================
// REMOVED: Discord Messages table (migrated to bridge_messages)
// Dropped in migration 0011_add_encrypted_metadata_drop_deprecated.sql
// ============================================

// ============================================
// Abuse Signals
// ============================================

export const abuseSignals = pgTable('abuse_signals', {
  /** Unique signal ID */
  id: text('id').primaryKey(),
  /** Reporter edge ID (optional - anonymous reporting allowed) */
  reporterEdgeId: text('reporter_edge_id').references(() => edges.id),
  /** Reported conversation ID */
  conversationId: text('conversation_id').references(() => conversations.id),
  /** Reported message ID */
  messageId: text('message_id').references(() => messages.id),
  /** Reason for report */
  reason: text('reason').notNull(),
  /** When report was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  convIdx: index('abuse_signals_conv_idx').on(table.conversationId),
  createdIdx: index('abuse_signals_created_idx').on(table.createdAt),
}));

// ============================================
// Rate Limit Ledger
// ============================================

export const rateLimitLedger = pgTable('rate_limit_ledger', {
  /** Unique entry ID */
  id: text('id').primaryKey(),
  /** Subject identifier (pubkey fingerprint, IP hash, etc.) */
  subjectId: text('subject_id').notNull(),
  /** Type of action being rate limited */
  actionType: text('action_type').notNull(),
  /** When this action occurred */
  timestamp: timestamp('timestamp', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  subjectActionIdx: index('rate_limit_subject_action_idx').on(table.subjectId, table.actionType),
  timestampIdx: index('rate_limit_timestamp_idx').on(table.timestamp),
}));

// ============================================
// Visitor Sessions (Contact Link Anonymous Users)
// ============================================

/**
 * Stores visitor sessions for Contact Link conversations.
 * Visitors derive a keypair from PIN + linkId client-side.
 * The encrypted ratchet state allows them to resume E2EE conversations
 * without the server ever seeing the PIN or private key.
 */
export const visitorSessions = pgTable('visitor_sessions', {
  /** Unique session ID (ulid) */
  id: text('id').primaryKey(),
  /** Contact link edge ID this visitor connected through */
  contactLinkEdgeId: text('contact_link_edge_id').references(() => edges.id).notNull(),
  /** Visitor's derived X25519 public key (from PIN + linkId) - their identity for this link */
  visitorPublicKey: text('visitor_public_key').notNull(),
  /** Visitor-provided display name (optional, not validated) */
  displayName: text('display_name'),
  /** Encrypted Double Ratchet state (encrypted with visitor's PIN-derived key)
   * Only the visitor can decrypt this - allows session resumption */
  encryptedRatchetState: text('encrypted_ratchet_state'),
  /** Encrypted message history (encrypted with visitor's key)
   * Stores decrypted messages so they can be restored on session resume */
  encryptedMessageHistory: text('encrypted_message_history'),
  /** Conversation ID for this visitor session */
  conversationId: text('conversation_id').references(() => conversations.id),
  /** PIN verification attempts counter (for rate limiting) */
  failedAttempts: integer('failed_attempts').default(0).notNull(),
  /** When last attempt was made (for rate limiting) */
  lastAttemptAt: timestamp('last_attempt_at', { withTimezone: true }),
  /** When session was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  /** Last activity timestamp */
  lastActivityAt: timestamp('last_activity_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  contactLinkIdx: index('visitor_sessions_contact_link_idx').on(table.contactLinkEdgeId),
  visitorKeyIdx: uniqueIndex('visitor_sessions_visitor_key_idx').on(table.contactLinkEdgeId, table.visitorPublicKey),
  conversationIdx: index('visitor_sessions_conversation_idx').on(table.conversationId),
}));

// ============================================
// Bridge Status Events (Connection Monitoring)
// ============================================

export type BridgeStatus = 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'failed';

/**
 * Tracks connection status history for bridge edges.
 * Used for monitoring bridge health, debugging connection issues, and analytics.
 */
export const bridgeStatusEvents = pgTable('bridge_status_events', {
  /** Unique event ID (ulid) */
  id: text('id').primaryKey(),
  /** Bridge edge ID (references edges table) */
  edgeId: text('edge_id').references(() => edges.id, { onDelete: 'cascade' }).notNull(),
  /** Connection status */
  status: text('status').notNull().$type<BridgeStatus>(),
  /** Previous status (for tracking state transitions) */
  previousStatus: text('previous_status').$type<BridgeStatus>(),
  /** Timestamp of this status change */
  timestamp: timestamp('timestamp', { withTimezone: true }).defaultNow().notNull(),
  /** Connection duration in milliseconds (for connected -> disconnected transitions) */
  connectionDurationMs: integer('connection_duration_ms'),
  /** Reconnection attempt number (for reconnecting/failed states) */
  reconnectAttempt: integer('reconnect_attempt'),
  /** Error message if status is 'failed' or 'reconnecting' */
  errorMessage: text('error_message'),
  /** Additional metadata (client info, network conditions, etc.) */
  metadata: jsonb('metadata').default({}).notNull(),
  /** When this record was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  edgeIdx: index('bridge_status_events_edge_id_idx').on(table.edgeId),
  timestampIdx: index('bridge_status_events_timestamp_idx').on(table.timestamp),
  statusIdx: index('bridge_status_events_status_idx').on(table.status),
  edgeTimestampIdx: index('bridge_status_events_edge_timestamp_idx').on(table.edgeId, table.timestamp),
}));

// ============================================
// Type exports
// ============================================

export type Identity = typeof identities.$inferSelect;
export type NewIdentity = typeof identities.$inferInsert;

// Handle types removed - handles are now native edges

export type Edge = typeof edges.$inferSelect;
export type NewEdge = typeof edges.$inferInsert;

export type Conversation = typeof conversations.$inferSelect;
export type NewConversation = typeof conversations.$inferInsert;

export type Message = typeof messages.$inferSelect;
export type NewMessage = typeof messages.$inferInsert;

export type BridgeMessage = typeof bridgeMessages.$inferSelect;
export type NewBridgeMessage = typeof bridgeMessages.$inferInsert;

export type ConversationParticipant = typeof conversationParticipants.$inferSelect;
export type NewConversationParticipant = typeof conversationParticipants.$inferInsert;

export type VisitorSession = typeof visitorSessions.$inferSelect;
export type NewVisitorSession = typeof visitorSessions.$inferInsert;

export type BridgeStatusEvent = typeof bridgeStatusEvents.$inferSelect;
export type NewBridgeStatusEvent = typeof bridgeStatusEvents.$inferInsert;
