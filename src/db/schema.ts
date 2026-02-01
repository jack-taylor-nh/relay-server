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
// Handles (User-Facing Persistent Identity)
// ============================================

export const handles = pgTable('handles', {
  /** Unique handle ID (UUID) */
  id: text('id').primaryKey(),
  /** Owner identity ID (fingerprint) */
  identityId: text('identity_id').references(() => identities.id, { onDelete: 'cascade' }).notNull(),
  /** Handle string (without @ prefix, e.g., 'alice') */
  handle: text('handle').notNull().unique(),
  /** Optional display name */
  displayName: text('display_name'),
  /** When handle was created */
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  /** When handle was last updated */
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  identityIdx: index('handles_identity_idx').on(table.identityId),
  handleIdx: index('handles_handle_idx').on(table.handle),
}));

// ============================================
// Edges (Contact Points - Unified Model)
// ============================================

export type EdgeType = 
  | 'native'        // Direct Relay-to-Relay (implicit)
  | 'email'         // Email alias @rlymsg.com
  | 'contact_link'  // Public contact form
  | 'discord'       // Discord bridge
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
  /** Owner identity ID (nullable when edge is burned for privacy) */
  identityId: text('identity_id').references(() => identities.id),
  /** Handle this edge belongs to (nullable when edge is burned for privacy) */
  handleId: text('handle_id').references(() => handles.id, { onDelete: 'cascade' }),
  /** Bridge type: email, native, discord, telegram, sms, etc. (NEW) */
  bridgeType: text('bridge_type').notNull().default('email'),
  /** True for native Relay-to-Relay edges (NEW) */
  isNative: boolean('is_native').default(false).notNull(),
  /** Bridge-specific metadata (credentials, config) as encrypted JSON (NEW) */
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
  identityIdx: index('edges_identity_idx').on(table.identityId),
  handleIdx: index('edges_handle_idx').on(table.handleId),
  addressIdx: uniqueIndex('edges_address_idx').on(table.address),
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
  /** User-friendly label for the channel (e.g., "Relayed via Email") */
  channelLabel: text('channel_label'),
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
  /** For Relay users: identity ID */
  identityId: text('identity_id').references(() => identities.id),
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
  identityIdx: index('conv_participants_identity_idx').on(table.identityId),
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
  /** Sender: identity ID for Relay users */
  senderIdentityId: text('sender_identity_id').references(() => identities.id),
  /** Sender: external ID for non-Relay contacts */
  senderExternalId: text('sender_external_id'),
  /** For e2ee: encrypted content (base64) */
  ciphertext: text('ciphertext'),
  /** Ephemeral public key for decryption (base64) */
  ephemeralPubkey: text('ephemeral_pubkey'),
  /** Nonce used for encryption (base64) */
  nonce: text('nonce'),
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
  senderIdentityIdx: index('messages_sender_identity_idx').on(table.senderIdentityId),
}));

// Note: emailAliases table removed - edges table now handles all contact surfaces

// ============================================
// Email Messages (metadata for email origin)
// ============================================

export const emailMessages = pgTable('email_messages', {
  /** References the message ID */
  messageId: text('message_id').references(() => messages.id).primaryKey(),
  /** Original sender email (hashed for privacy) */
  fromAddressHash: text('from_address_hash').notNull(),
  /** Subject line */
  subject: text('subject'),
  /** Message-ID header for threading */
  emailMessageId: text('email_message_id'),
  /** In-Reply-To header for threading */
  inReplyTo: text('in_reply_to'),
});

// ============================================
// Abuse Signals
// ============================================

export const abuseSignals = pgTable('abuse_signals', {
  /** Unique signal ID */
  id: text('id').primaryKey(),
  /** Reporter identity ID */
  reporterIdentityId: text('reporter_identity_id').references(() => identities.id).notNull(),
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
// Type exports
// ============================================

export type Identity = typeof identities.$inferSelect;
export type NewIdentity = typeof identities.$inferInsert;

export type Handle = typeof handles.$inferSelect;
export type NewHandle = typeof handles.$inferInsert;

export type Edge = typeof edges.$inferSelect;
export type NewEdge = typeof edges.$inferInsert;

export type Conversation = typeof conversations.$inferSelect;
export type NewConversation = typeof conversations.$inferInsert;

export type Message = typeof messages.$inferSelect;
export type NewMessage = typeof messages.$inferInsert;

export type ConversationParticipant = typeof conversationParticipants.$inferSelect;
export type NewConversationParticipant = typeof conversationParticipants.$inferInsert;
