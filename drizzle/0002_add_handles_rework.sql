-- Migration: Handle → Edges Architecture Rework
-- Adds proper handles table, updates edges to reference handles

-- Step 1: Drop old handles table if exists
DROP TABLE IF EXISTS handles CASCADE;

-- Step 2: Create new handles table
CREATE TABLE handles (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  handle TEXT NOT NULL UNIQUE,
  display_name TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Step 3: Create indexes
CREATE INDEX handles_identity_idx ON handles(identity_id);
CREATE INDEX handles_handle_idx ON handles(handle);

-- Step 4: Add bridge fields to edges
ALTER TABLE edges ADD COLUMN bridge_type TEXT;
ALTER TABLE edges ADD COLUMN is_native BOOLEAN DEFAULT false;
ALTER TABLE edges ADD COLUMN metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE edges ADD COLUMN handle_id TEXT REFERENCES handles(id) ON DELETE CASCADE;

-- Step 5: Update existing edges with default values
UPDATE edges SET bridge_type = 'email' WHERE bridge_type IS NULL;
UPDATE edges SET is_native = false WHERE is_native IS NULL;
UPDATE edges SET metadata = '{}'::jsonb WHERE metadata IS NULL;

-- Step 6: Make bridge fields NOT NULL after populating
ALTER TABLE edges ALTER COLUMN bridge_type SET NOT NULL;
ALTER TABLE edges ALTER COLUMN is_native SET NOT NULL;
ALTER TABLE edges ALTER COLUMN metadata SET NOT NULL;

-- Step 7: Create index for handle_id
CREATE INDEX edges_handle_idx ON edges(handle_id);

-- Step 8: Create default handles for existing identities with edges
INSERT INTO handles (id, identity_id, handle, display_name, created_at, updated_at)
SELECT 
  gen_random_uuid()::text,
  identity_id,
  'user_' || substring(identity_id, 1, 8),
  NULL,
  NOW(),
  NOW()
FROM (
  SELECT DISTINCT identity_id 
  FROM edges 
  WHERE identity_id IS NOT NULL
) AS distinct_identities;

-- Step 9: Update edges to reference their identity's handle
UPDATE edges e
SET handle_id = h.id
FROM handles h
WHERE e.identity_id = h.identity_id
AND e.handle_id IS NULL;
