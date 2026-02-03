-- Add discord_messages table for Discord-specific message metadata
-- Stores Discord user IDs for reply routing

CREATE TABLE IF NOT EXISTS discord_messages (
  message_id TEXT PRIMARY KEY REFERENCES messages(id),
  sender_discord_id TEXT NOT NULL,
  sender_discord_tag TEXT,
  discord_message_id TEXT
);

-- Index for looking up by Discord user ID
CREATE INDEX IF NOT EXISTS discord_messages_sender_idx ON discord_messages(sender_discord_id);
