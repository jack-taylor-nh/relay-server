-- Migration: Add handles table and update edges for handle-based architecture
-- This enables disposable edges, native Relay-to-Relay, and future bridges

-- Step 1: Create handles table
CREATE TABLE IF NOT EXISTS handles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  handle VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_handle_per_identity UNIQUE (identity_id, handle)
);

-- Index for fast lookups
CREATE INDEX idx_handles_identity ON handles(identity_id);
CREATE INDEX idx_handles_handle ON handles(handle);

-- Step 2: Add new columns to edges table
ALTER TABLE edges 
  ADD COLUMN IF NOT EXISTS handle_id UUID REFERENCES handles(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS bridge_type VARCHAR(50) DEFAULT 'email',
  ADD COLUMN IF NOT EXISTS is_native BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- Step 3: Create temporary handles from existing edges
-- Each existing identity gets a temporary handle based on their first edge
INSERT INTO handles (identity_id, handle, display_name)
SELECT DISTINCT 
  e.identity_id,
  CONCAT('user_', SUBSTRING(e.identity_id::text, 1, 8)),
  NULL
FROM edges e
WHERE NOT EXISTS (
  SELECT 1 FROM handles h WHERE h.identity_id = e.identity_id
);

-- Step 4: Populate handle_id in edges table
UPDATE edges e
SET handle_id = h.id
FROM handles h
WHERE e.identity_id = h.identity_id
  AND e.handle_id IS NULL;

-- Step 5: Set bridge_type for existing email edges
UPDATE edges
SET bridge_type = 'email'
WHERE bridge_type IS NULL;

-- Step 6: Make handle_id NOT NULL now that data is migrated
ALTER TABLE edges
  ALTER COLUMN handle_id SET NOT NULL;

-- Step 7: Add indexes for performance
CREATE INDEX idx_edges_handle ON edges(handle_id);
CREATE INDEX idx_edges_bridge_type ON edges(bridge_type);
CREATE INDEX idx_edges_is_native ON edges(is_native) WHERE is_native = TRUE;

-- Step 8: Add unique constraint for native edges (one per handle)
CREATE UNIQUE INDEX idx_edges_native_handle ON edges(handle_id) WHERE is_native = TRUE;

-- Note: We keep identity_id on edges for backward compatibility during transition
-- In a future migration, we can drop it after updating all application code
-- For now, both identity_id and handle_id coexist

COMMENT ON TABLE handles IS 'Persistent user handles (e.g., @alice) - user-facing identity';
COMMENT ON COLUMN handles.handle IS 'Human-readable handle without @ prefix';
COMMENT ON COLUMN edges.handle_id IS 'Handle this edge belongs to (replaces direct identity_id link)';
COMMENT ON COLUMN edges.bridge_type IS 'Type of communication bridge: email, native, discord, telegram, sms, etc.';
COMMENT ON COLUMN edges.is_native IS 'True for native Relay-to-Relay edges (@alice)';
COMMENT ON COLUMN edges.metadata IS 'Bridge-specific configuration (credentials, settings) stored as encrypted JSON';
