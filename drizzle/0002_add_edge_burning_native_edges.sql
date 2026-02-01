-- Migration: Add edge burning and handle→native edge architecture
-- Date: 2026-02-01
-- 
-- Changes:
-- 1. Add 'burned' status to edge_status enum
-- 2. Make edges.identity_id nullable (for burned edges)
-- 3. Make edges.handle_id nullable (for burned edges)

-- Add 'burned' status to edge status
-- Note: PostgreSQL text columns don't need ALTER, just start using the new value

-- Make identityId nullable for burned edges (allows unlinking)
ALTER TABLE edges ALTER COLUMN identity_id DROP NOT NULL;

-- Update comment to reflect new nullable behavior
COMMENT ON COLUMN edges.identity_id IS 'Owner identity ID (nullable when edge is burned for privacy)';
COMMENT ON COLUMN edges.handle_id IS 'Handle this edge belongs to (nullable when edge is burned for privacy)';

-- Create native edges for existing handles
-- This ensures all handles have their native edge
DO $$
DECLARE
  handle_record RECORD;
  edge_id TEXT;
BEGIN
  FOR handle_record IN 
    SELECT h.id, h.identity_id, h.handle, h.created_at
    FROM handles h
    WHERE NOT EXISTS (
      SELECT 1 FROM edges e 
      WHERE e.handle_id = h.id AND e.is_native = true
    )
  LOOP
    -- Generate ULID-like ID for edge (simplified version)
    edge_id := gen_random_uuid()::text;
    
    -- Create native edge
    INSERT INTO edges (
      id,
      identity_id,
      handle_id,
      type,
      bridge_type,
      is_native,
      address,
      status,
      security_level,
      metadata,
      created_at,
      message_count
    ) VALUES (
      edge_id,
      handle_record.identity_id,
      handle_record.id,
      'native',
      'native',
      true,
      handle_record.handle,
      'active',
      'e2ee',
      '{}'::jsonb,
      handle_record.created_at,
      0
    );
  END LOOP;
END $$;
