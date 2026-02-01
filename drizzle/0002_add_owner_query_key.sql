-- Migration: Add owner query key for zero-knowledge edge ownership
-- Date: 2025-02-01
-- Description: Implements encrypted query key approach per RELAY_ETHOS.md

-- Add owner_query_key column (nullable for backwards compatibility during backfill)
ALTER TABLE edges ADD COLUMN owner_query_key TEXT;

-- Create index for fast filtering by query key
CREATE INDEX IF NOT EXISTS edges_owner_query_key_idx ON edges(owner_query_key);

-- Drop foreign key constraint on identity_id (architectural isolation)
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_identity_id_identities_id_fk;

-- Drop handle_id column (handles deprecated - now using edges only)
ALTER TABLE edges DROP COLUMN IF EXISTS handle_id;

-- Drop handle_id index (no longer needed)
DROP INDEX IF EXISTS edges_handle_idx;

-- Note: Backfill existing edges with owner_query_key using separate script
-- See: scripts/backfill-query-keys.ts
