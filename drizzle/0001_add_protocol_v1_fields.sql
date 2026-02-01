-- Migration: Add protocol v1 fields
-- Created: 2026-01-31

-- ============================================
-- Identities: Add home_server column
-- ============================================

ALTER TABLE identities 
ADD COLUMN IF NOT EXISTS home_server TEXT NOT NULL DEFAULT 'userelay.org';

-- Update status enum to include 'hidden' (PostgreSQL approach: check constraint)
-- First drop old constraint if exists, then add new one
ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_status_check;
ALTER TABLE identities ADD CONSTRAINT identities_status_check 
  CHECK (status IN ('active', 'locked', 'hidden'));

-- ============================================
-- Messages: Add protocol fields
-- ============================================

ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS protocol_version TEXT NOT NULL DEFAULT '1.0';

ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS edge_id TEXT REFERENCES edges(id);

ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS origin TEXT;

ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS security_level TEXT NOT NULL DEFAULT 'e2ee';

ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT 'text/plain';

-- Add constraint for security_level
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_security_level_check;
ALTER TABLE messages ADD CONSTRAINT messages_security_level_check 
  CHECK (security_level IN ('e2ee', 'gateway_secured'));

-- ============================================
-- Conversations: Update security_level to support 'mixed'
-- ============================================

ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_security_level_check;
ALTER TABLE conversations ADD CONSTRAINT conversations_security_level_check 
  CHECK (security_level IN ('e2ee', 'gateway_secured', 'mixed'));

-- ============================================
-- Indexes for new columns
-- ============================================

CREATE INDEX IF NOT EXISTS messages_edge_idx ON messages(edge_id);
CREATE INDEX IF NOT EXISTS messages_origin_idx ON messages(origin);
CREATE INDEX IF NOT EXISTS messages_security_level_idx ON messages(security_level);
