-- Migration: Add x25519_public_key to edges
-- Created: 2026-01-31

ALTER TABLE edges 
ADD COLUMN IF NOT EXISTS x25519_public_key TEXT;

-- For existing edges, we'll need to regenerate them or have users create new ones
-- The x25519 key cannot be derived from Ed25519 public key alone
