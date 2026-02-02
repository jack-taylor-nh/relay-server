-- Migration: NULL out identity_id in edges table
-- 
-- SECURITY FIX: The identity_id column in edges completely defeats
-- the purpose of ownerQueryKey. With identity_id stored in plaintext,
-- an attacker with DB access can trivially link any edge to its owner.
--
-- After this migration:
-- - edges.identity_id will be NULL for all existing edges
-- - New edges will not store identity_id (code change)
-- - Edge ownership is verified via ownerQueryKey cryptographically
-- - The column remains for schema compatibility but is deprecated

-- NULL out all existing identity_id values in edges
UPDATE edges
SET identity_id = NULL
WHERE identity_id IS NOT NULL
  AND status != 'burned';  -- Already burned edges have NULL identity_id

-- Add deprecation comment
COMMENT ON COLUMN edges.identity_id IS 'DEPRECATED: Do not use. Use owner_query_key for ownership verification. Kept for schema compatibility only.';
