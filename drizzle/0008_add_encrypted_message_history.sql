-- Add encrypted message history to visitor sessions
-- This stores the visitor's decrypted chat history encrypted with their key
-- Allows session restoration with full message history

ALTER TABLE "visitor_sessions" ADD COLUMN "encrypted_message_history" text;
