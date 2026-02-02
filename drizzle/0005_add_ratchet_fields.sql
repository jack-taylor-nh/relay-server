-- Migration: Add Double Ratchet fields to messages
-- These fields are required for proper Double Ratchet decryption

-- Previous chain length (pn) - needed for handling DH ratchet steps
ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS ratchet_pn INTEGER DEFAULT 0;

-- Message number (n) - the message number in the current chain
ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS ratchet_n INTEGER DEFAULT 0;

-- Comment: The existing fields are repurposed:
-- ciphertext: contains the encrypted message content
-- ephemeral_pubkey: contains the ratchet DH public key (dh)
-- nonce: contains the AEAD nonce
