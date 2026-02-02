-- Migration: NULL out identityId in conversation_participants
-- 
-- SECURITY FIX: The identityId column in conversation_participants defeats
-- edge-based unlinkability. With identityId stored, an attacker with DB access
-- can link all conversations back to their owning identity.
--
-- After this migration:
-- - conversation_participants will use edgeId only for ownership lookups
-- - Existing identityId values are NULLed to break historical linkage
-- - The column remains for backwards compatibility but should not be written

-- NULL out all existing identityId values
UPDATE conversation_participants
SET identity_id = NULL
WHERE identity_id IS NOT NULL;

-- Optional: Add a comment to the column documenting its deprecated status
COMMENT ON COLUMN conversation_participants.identity_id IS 'DEPRECATED: Do not use. Use edge_id for participant ownership. Kept for schema compatibility only.';
