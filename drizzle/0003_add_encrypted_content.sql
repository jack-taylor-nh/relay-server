-- Add encrypted_content column for zero-knowledge message storage
ALTER TABLE messages ADD COLUMN IF NOT EXISTS encrypted_content TEXT;

