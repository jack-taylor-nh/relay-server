-- Add visitor_sessions table for Contact Link anonymous users
-- Visitors derive keypairs from PIN + linkId for E2EE conversations

CREATE TABLE IF NOT EXISTS "visitor_sessions" (
  "id" text PRIMARY KEY NOT NULL,
  "contact_link_edge_id" text NOT NULL REFERENCES "edges"("id"),
  "visitor_public_key" text NOT NULL,
  "display_name" text,
  "encrypted_ratchet_state" text,
  "conversation_id" text REFERENCES "conversations"("id"),
  "failed_attempts" integer DEFAULT 0 NOT NULL,
  "last_attempt_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_activity_at" timestamp with time zone DEFAULT now() NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS "visitor_sessions_contact_link_idx" ON "visitor_sessions" ("contact_link_edge_id");
CREATE UNIQUE INDEX IF NOT EXISTS "visitor_sessions_visitor_key_idx" ON "visitor_sessions" ("contact_link_edge_id", "visitor_public_key");
CREATE INDEX IF NOT EXISTS "visitor_sessions_conversation_idx" ON "visitor_sessions" ("conversation_id");
