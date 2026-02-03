-- Add bridge_metadata column to conversations table
-- This stores bridge-specific data (e.g., Discord conversationMessageId)
-- that workers need but isn't user-sensitive

ALTER TABLE conversations 
ADD COLUMN IF NOT EXISTS bridge_metadata JSONB DEFAULT NULL;

-- Add index for querying by bridge metadata properties if needed
CREATE INDEX IF NOT EXISTS conversations_bridge_metadata_idx 
ON conversations USING GIN (bridge_metadata) 
WHERE bridge_metadata IS NOT NULL;
