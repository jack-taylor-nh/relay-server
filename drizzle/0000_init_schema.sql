-- Relay Database Schema
-- Run this first to create all tables

-- ============================================
-- Identities (Core Anchor)
-- ============================================

CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  home_server TEXT NOT NULL DEFAULT 'userelay.org',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'locked', 'hidden')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ
);

-- ============================================
-- Handles (Optional, Multiple per Identity)
-- ============================================

CREATE TABLE IF NOT EXISTS handles (
  name TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id),
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'reserved')),
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  disabled_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS handles_identity_idx ON handles(identity_id);

-- ============================================
-- Edges (Contact Points - Unified Model)
-- ============================================

CREATE TABLE IF NOT EXISTS edges (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id),
  type TEXT NOT NULL,
  address TEXT NOT NULL,
  label TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'rotated')),
  security_level TEXT NOT NULL CHECK (security_level IN ('e2ee', 'gateway_secured')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  disabled_at TIMESTAMPTZ,
  rotated_from_edge_id TEXT,
  policy JSONB,
  message_count INTEGER NOT NULL DEFAULT 0,
  last_activity_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS edges_identity_idx ON edges(identity_id);
CREATE UNIQUE INDEX IF NOT EXISTS edges_address_idx ON edges(address);
CREATE INDEX IF NOT EXISTS edges_type_idx ON edges(type);

-- ============================================
-- Auth Nonces (short-lived)
-- ============================================

CREATE TABLE IF NOT EXISTS auth_nonces (
  nonce TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- Conversations
-- ============================================

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  origin TEXT NOT NULL,
  edge_id TEXT REFERENCES edges(id),
  security_level TEXT NOT NULL CHECK (security_level IN ('e2ee', 'gateway_secured', 'mixed')),
  channel_label TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS conversations_edge_idx ON conversations(edge_id);
CREATE INDEX IF NOT EXISTS conversations_origin_idx ON conversations(origin);

-- ============================================
-- Conversation Participants
-- ============================================

CREATE TABLE IF NOT EXISTS conversation_participants (
  conversation_id TEXT NOT NULL REFERENCES conversations(id),
  identity_id TEXT REFERENCES identities(id),
  external_id TEXT,
  display_name TEXT,
  is_owner BOOLEAN NOT NULL DEFAULT FALSE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS conv_participants_conv_idx ON conversation_participants(conversation_id);
CREATE INDEX IF NOT EXISTS conv_participants_identity_idx ON conversation_participants(identity_id);
CREATE INDEX IF NOT EXISTS conv_participants_external_idx ON conversation_participants(external_id);

-- ============================================
-- Messages
-- ============================================

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  protocol_version TEXT NOT NULL DEFAULT '1.0',
  conversation_id TEXT NOT NULL REFERENCES conversations(id),
  edge_id TEXT REFERENCES edges(id),
  origin TEXT,
  security_level TEXT NOT NULL DEFAULT 'e2ee' CHECK (security_level IN ('e2ee', 'gateway_secured')),
  content_type TEXT NOT NULL DEFAULT 'text/plain',
  sender_identity_id TEXT REFERENCES identities(id),
  sender_external_id TEXT,
  ciphertext TEXT,
  ephemeral_pubkey TEXT,
  nonce TEXT,
  plaintext_content TEXT,
  signature TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS messages_conv_idx ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS messages_created_idx ON messages(created_at);
CREATE INDEX IF NOT EXISTS messages_sender_identity_idx ON messages(sender_identity_id);
CREATE INDEX IF NOT EXISTS messages_edge_idx ON messages(edge_id);
CREATE INDEX IF NOT EXISTS messages_origin_idx ON messages(origin);

-- ============================================
-- Email Messages (metadata for email origin)
-- ============================================

CREATE TABLE IF NOT EXISTS email_messages (
  message_id TEXT PRIMARY KEY REFERENCES messages(id),
  from_address_hash TEXT NOT NULL,
  subject TEXT,
  email_message_id TEXT,
  in_reply_to TEXT
);

-- ============================================
-- Abuse Signals
-- ============================================

CREATE TABLE IF NOT EXISTS abuse_signals (
  id TEXT PRIMARY KEY,
  reporter_identity_id TEXT NOT NULL REFERENCES identities(id),
  conversation_id TEXT REFERENCES conversations(id),
  message_id TEXT REFERENCES messages(id),
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS abuse_signals_conv_idx ON abuse_signals(conversation_id);
CREATE INDEX IF NOT EXISTS abuse_signals_created_idx ON abuse_signals(created_at);

-- ============================================
-- Rate Limit Ledger
-- ============================================

CREATE TABLE IF NOT EXISTS rate_limit_ledger (
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS rate_limit_subject_action_idx ON rate_limit_ledger(subject_id, action_type);
CREATE INDEX IF NOT EXISTS rate_limit_timestamp_idx ON rate_limit_ledger(timestamp);
