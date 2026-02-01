-- Migration: Convert handles to pure edge model
-- 
-- This migration:
-- 1. Adds display_name to edges.metadata for native edges
-- 2. Sets bridgeType='native' and isNative=true for all native edges
-- 3. Ensures all handles have corresponding native edges
-- 4. Moves handle metadata into edge metadata

-- Update existing native edges to include handle info in metadata
UPDATE edges
SET metadata = jsonb_build_object(
  'handle', h.handle,
  'displayName', h.display_name
)
FROM handles h
WHERE edges.handle_id = h.id
  AND edges.is_native = true
  AND edges.metadata = '{}';

-- Create native edges for any orphaned handles (shouldn't exist but safety check)
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
  created_at
)
SELECT
  'EDGE_' || h.id,  -- Temporary prefix to avoid collisions
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
  h.created_at
FROM handles h
WHERE NOT EXISTS (
  SELECT 1 FROM edges e
  WHERE e.handle_id = h.id AND e.is_native = true
)
ON CONFLICT (id) DO NOTHING;

-- Note: We're NOT dropping the handles table yet to maintain backwards compatibility
-- After all clients are updated, we can drop it in a future migration
