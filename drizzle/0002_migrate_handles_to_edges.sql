-- Migration: Convert handles to pure edge model
-- 
-- This migration:
-- 1. Adds display_name and handle to edges.metadata for existing native edges
-- 2. Creates native edges ONLY for orphaned handles (handles without native edges)

-- Step 1: Update existing native edges to include handle info in metadata
UPDATE edges
SET metadata = jsonb_build_object(
  'handle', h.handle,
  'displayName', h.display_name
)
FROM handles h
WHERE edges.handle_id = h.id
  AND edges.is_native = true
  AND (edges.metadata IS NULL OR edges.metadata = '{}');

-- Step 2: Create native edges ONLY for orphaned handles (safety check)
-- This should rarely happen since we auto-create them now
INSERT INTO edges (
  id,
  identity_id,
  handle_id,
  type,
  address,
  status,
  security_level,
  bridge_type,
  is_native,
  metadata,
  x25519_public_key,
  created_at
)
SELECT
  'MIGRATED_' || h.id,  -- Prefix to avoid collisions
  h.identity_id,
  h.id,
  'native',
  h.identity_id,  -- Native edges use identity ID as address
  'active',
  'e2ee',
  'native',
  true,
  jsonb_build_object(
    'handle', h.handle,
    'displayName', h.display_name
  ),
  NULL,  -- x25519 key will need to be regenerated
  h.created_at
FROM handles h
WHERE h.identity_id IS NOT NULL  -- Skip already-burned handles
  AND NOT EXISTS (
    SELECT 1 FROM edges e
    WHERE e.handle_id = h.id AND e.is_native = true
  )
  AND NOT EXISTS (
    SELECT 1 FROM edges e
    WHERE e.address = h.identity_id  -- Avoid address collision
  )
ON CONFLICT (id) DO NOTHING;

-- Note: We're NOT dropping the handles table yet to maintain backwards compatibility
-- After all clients are updated, we can drop it in a future migration
