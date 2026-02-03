-- Migration: Add encrypted_metadata to conversations, drop deprecated tables
-- This enables client-side decryption of counterparty names in inbox view

-- Step 1: Add encrypted_metadata column to conversations
-- This stores counterparty display info encrypted for the edge's X25519 key
-- Only the client can decrypt it - server stores opaque blob
ALTER TABLE conversations ADD COLUMN IF NOT EXISTS encrypted_metadata TEXT;

-- Step 2: Drop channel_label column (deprecated - was plaintext privacy leak)
-- For native conversations: counterparty handle is now resolved from participants table
-- For bridge conversations: counterparty info is in encrypted_metadata
ALTER TABLE conversations DROP COLUMN IF EXISTS channel_label;

-- Step 3: Drop deprecated email_messages table
-- All email metadata is now stored in bridge_messages
DROP TABLE IF EXISTS email_messages;

-- Step 4: Drop deprecated discord_messages table
-- All discord metadata is now stored in bridge_messages
DROP TABLE IF EXISTS discord_messages;

-- Add comment explaining the encrypted_metadata format:
-- The encrypted_metadata is a NaCl box encrypted for the edge's X25519 public key
-- Format after decryption: { counterpartyDisplayName: string, counterpartyPlatformId?: string }
-- Bridge workers encrypt this when creating conversations
-- Only the Relay client with the edge's private key can decrypt
COMMENT ON COLUMN conversations.encrypted_metadata IS 'Encrypted counterparty info (NaCl box for edge X25519 key). Contains displayName, etc. Only client can decrypt.';
