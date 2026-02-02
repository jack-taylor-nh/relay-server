-- Migration: Drop handles table and anonymize abuse_signals
-- 
-- ARCHITECTURAL CHANGES:
-- 
-- 1. HANDLES TABLE DROPPED
--    The handles table is redundant with native edges.
--    A "handle" is now just a native edge with:
--    - type = 'native'
--    - address = handle name (e.g., 'alice')
--    - ownerQueryKey = HMAC(identityId, secret) for ownership
--    
--    Benefits:
--    - No identity_id column leaking ownership
--    - Unified edge-based architecture
--    - Handles are burnable like any other edge
--
-- 2. ABUSE_SIGNALS ANONYMIZED
--    - Removed reporter_identity_id (was NOT NULL)
--    - Added optional reporter_edge_id (nullable for anonymous reports)
--    - Reports can now be submitted without identifying the reporter

-- Step 1: Add new column to abuse_signals
ALTER TABLE abuse_signals 
ADD COLUMN IF NOT EXISTS reporter_edge_id TEXT REFERENCES edges(id);

-- Step 2: Make reporter_identity_id nullable (preparation for removal)
ALTER TABLE abuse_signals 
ALTER COLUMN reporter_identity_id DROP NOT NULL;

-- Step 3: NULL out existing reporter_identity_id values for anonymity
UPDATE abuse_signals 
SET reporter_identity_id = NULL 
WHERE reporter_identity_id IS NOT NULL;

-- Step 4: Drop the handles table
-- First, ensure any foreign key constraints are handled
DROP TABLE IF EXISTS handles CASCADE;

-- Step 5: Add deprecation comments
COMMENT ON COLUMN abuse_signals.reporter_identity_id IS 'DEPRECATED: Will be dropped in future migration. Use reporter_edge_id for semi-anonymous reporting or NULL for fully anonymous.';
