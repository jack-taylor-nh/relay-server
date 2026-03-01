CREATE TABLE "abuse_signals" (
	"id" text PRIMARY KEY NOT NULL,
	"reporter_edge_id" text,
	"conversation_id" text,
	"message_id" text,
	"reason" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_nonces" (
	"nonce" text PRIMARY KEY NOT NULL,
	"identity_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "bridge_messages" (
	"message_id" text PRIMARY KEY NOT NULL,
	"bridge_type" text NOT NULL,
	"sender_external_id" text NOT NULL,
	"sender_display_name" text,
	"platform_message_id" text,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE TABLE "bridge_status_events" (
	"id" text PRIMARY KEY NOT NULL,
	"edge_id" text NOT NULL,
	"status" text NOT NULL,
	"previous_status" text,
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL,
	"connection_duration_ms" integer,
	"reconnect_attempt" integer,
	"error_message" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "conversation_participants" (
	"conversation_id" text NOT NULL,
	"edge_id" text,
	"external_id" text,
	"display_name" text,
	"is_owner" boolean DEFAULT false NOT NULL,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "conversations" (
	"id" text PRIMARY KEY NOT NULL,
	"origin" text NOT NULL,
	"edge_id" text,
	"security_level" text NOT NULL,
	"encrypted_metadata" text,
	"bridge_metadata" jsonb,
	"ratchet_state" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_activity_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "edges" (
	"id" text PRIMARY KEY NOT NULL,
	"owner_query_key" text,
	"bridge_type" text DEFAULT 'email' NOT NULL,
	"is_native" boolean DEFAULT false NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"type" text NOT NULL,
	"address" text NOT NULL,
	"label" text,
	"status" text DEFAULT 'active' NOT NULL,
	"security_level" text NOT NULL,
	"x25519_public_key" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"disabled_at" timestamp with time zone,
	"rotated_from_edge_id" text,
	"policy" jsonb,
	"message_count" integer DEFAULT 0 NOT NULL,
	"last_activity_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "files" (
	"id" text PRIMARY KEY NOT NULL,
	"conversation_id" text NOT NULL,
	"message_id" text,
	"uploader_edge_id" text,
	"uploader_query_key" text,
	"encrypted_filename" text,
	"mime_type" text DEFAULT 'application/octet-stream' NOT NULL,
	"size_bytes" integer NOT NULL,
	"storage_key" text NOT NULL,
	"storage_bucket" text DEFAULT 'relay-files' NOT NULL,
	"cdn_url" text,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	"expires_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"id" text PRIMARY KEY NOT NULL,
	"public_key" text NOT NULL,
	"home_server" text DEFAULT 'userelay.org' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "messages" (
	"id" text PRIMARY KEY NOT NULL,
	"protocol_version" text DEFAULT '1.0' NOT NULL,
	"conversation_id" text NOT NULL,
	"edge_id" text,
	"origin" text,
	"security_level" text DEFAULT 'e2ee' NOT NULL,
	"content_type" text DEFAULT 'text/plain' NOT NULL,
	"sender_external_id" text,
	"ciphertext" text,
	"ephemeral_pubkey" text,
	"nonce" text,
	"ratchet_pn" integer,
	"ratchet_n" integer,
	"encrypted_content" text,
	"plaintext_content" text,
	"signature" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rate_limit_ledger" (
	"id" text PRIMARY KEY NOT NULL,
	"subject_id" text NOT NULL,
	"action_type" text NOT NULL,
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "redemption_codes" (
	"id" text PRIMARY KEY NOT NULL,
	"code" text NOT NULL,
	"type" text NOT NULL,
	"asset_type" text NOT NULL,
	"value" integer,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"redeemed_at" timestamp with time zone,
	"failed_attempts" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "redemption_codes_code_unique" UNIQUE("code")
);
--> statement-breakpoint
CREATE TABLE "redemption_receipts" (
	"id" text PRIMARY KEY NOT NULL,
	"receipt_key" text NOT NULL,
	"code_id" text NOT NULL,
	"redeemed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "redemption_receipts_receipt_key_unique" UNIQUE("receipt_key")
);
--> statement-breakpoint
CREATE TABLE "visitor_sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"contact_link_edge_id" text NOT NULL,
	"visitor_public_key" text NOT NULL,
	"display_name" text,
	"encrypted_ratchet_state" text,
	"encrypted_message_history" text,
	"conversation_id" text,
	"failed_attempts" integer DEFAULT 0 NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_activity_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "abuse_signals" ADD CONSTRAINT "abuse_signals_reporter_edge_id_edges_id_fk" FOREIGN KEY ("reporter_edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "abuse_signals" ADD CONSTRAINT "abuse_signals_conversation_id_conversations_id_fk" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "abuse_signals" ADD CONSTRAINT "abuse_signals_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_nonces" ADD CONSTRAINT "auth_nonces_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bridge_messages" ADD CONSTRAINT "bridge_messages_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bridge_status_events" ADD CONSTRAINT "bridge_status_events_edge_id_edges_id_fk" FOREIGN KEY ("edge_id") REFERENCES "public"."edges"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "conversation_participants" ADD CONSTRAINT "conversation_participants_conversation_id_conversations_id_fk" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "conversation_participants" ADD CONSTRAINT "conversation_participants_edge_id_edges_id_fk" FOREIGN KEY ("edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_edge_id_edges_id_fk" FOREIGN KEY ("edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "files" ADD CONSTRAINT "files_conversation_id_conversations_id_fk" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "files" ADD CONSTRAINT "files_message_id_messages_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."messages"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "files" ADD CONSTRAINT "files_uploader_edge_id_edges_id_fk" FOREIGN KEY ("uploader_edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_conversation_id_conversations_id_fk" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "messages" ADD CONSTRAINT "messages_edge_id_edges_id_fk" FOREIGN KEY ("edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "redemption_receipts" ADD CONSTRAINT "redemption_receipts_code_id_redemption_codes_id_fk" FOREIGN KEY ("code_id") REFERENCES "public"."redemption_codes"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "visitor_sessions" ADD CONSTRAINT "visitor_sessions_contact_link_edge_id_edges_id_fk" FOREIGN KEY ("contact_link_edge_id") REFERENCES "public"."edges"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "visitor_sessions" ADD CONSTRAINT "visitor_sessions_conversation_id_conversations_id_fk" FOREIGN KEY ("conversation_id") REFERENCES "public"."conversations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "abuse_signals_conv_idx" ON "abuse_signals" USING btree ("conversation_id");--> statement-breakpoint
CREATE INDEX "abuse_signals_created_idx" ON "abuse_signals" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "bridge_messages_bridge_type_idx" ON "bridge_messages" USING btree ("bridge_type");--> statement-breakpoint
CREATE INDEX "bridge_messages_sender_idx" ON "bridge_messages" USING btree ("sender_external_id");--> statement-breakpoint
CREATE INDEX "bridge_status_events_edge_id_idx" ON "bridge_status_events" USING btree ("edge_id");--> statement-breakpoint
CREATE INDEX "bridge_status_events_timestamp_idx" ON "bridge_status_events" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX "bridge_status_events_status_idx" ON "bridge_status_events" USING btree ("status");--> statement-breakpoint
CREATE INDEX "bridge_status_events_edge_timestamp_idx" ON "bridge_status_events" USING btree ("edge_id","timestamp");--> statement-breakpoint
CREATE INDEX "conv_participants_conv_idx" ON "conversation_participants" USING btree ("conversation_id");--> statement-breakpoint
CREATE INDEX "conv_participants_edge_idx" ON "conversation_participants" USING btree ("edge_id");--> statement-breakpoint
CREATE INDEX "conv_participants_external_idx" ON "conversation_participants" USING btree ("external_id");--> statement-breakpoint
CREATE INDEX "conversations_edge_idx" ON "conversations" USING btree ("edge_id");--> statement-breakpoint
CREATE INDEX "conversations_origin_idx" ON "conversations" USING btree ("origin");--> statement-breakpoint
CREATE INDEX "edges_owner_query_key_idx" ON "edges" USING btree ("owner_query_key");--> statement-breakpoint
CREATE UNIQUE INDEX "edges_type_address_idx" ON "edges" USING btree ("type","address");--> statement-breakpoint
CREATE INDEX "edges_type_idx" ON "edges" USING btree ("type");--> statement-breakpoint
CREATE INDEX "edges_bridge_type_idx" ON "edges" USING btree ("bridge_type");--> statement-breakpoint
CREATE INDEX "edges_is_native_idx" ON "edges" USING btree ("is_native");--> statement-breakpoint
CREATE INDEX "files_conversation_idx" ON "files" USING btree ("conversation_id");--> statement-breakpoint
CREATE INDEX "files_message_idx" ON "files" USING btree ("message_id");--> statement-breakpoint
CREATE INDEX "files_uploader_query_key_idx" ON "files" USING btree ("uploader_query_key");--> statement-breakpoint
CREATE INDEX "files_status_idx" ON "files" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "files_storage_key_idx" ON "files" USING btree ("storage_key");--> statement-breakpoint
CREATE INDEX "messages_conv_idx" ON "messages" USING btree ("conversation_id");--> statement-breakpoint
CREATE INDEX "messages_created_idx" ON "messages" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "rate_limit_subject_action_idx" ON "rate_limit_ledger" USING btree ("subject_id","action_type");--> statement-breakpoint
CREATE INDEX "rate_limit_timestamp_idx" ON "rate_limit_ledger" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX "redemption_codes_code_idx" ON "redemption_codes" USING btree ("code");--> statement-breakpoint
CREATE INDEX "redemption_codes_status_idx" ON "redemption_codes" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "redemption_receipts_receipt_key_idx" ON "redemption_receipts" USING btree ("receipt_key");--> statement-breakpoint
CREATE INDEX "redemption_receipts_code_id_idx" ON "redemption_receipts" USING btree ("code_id");--> statement-breakpoint
CREATE INDEX "visitor_sessions_contact_link_idx" ON "visitor_sessions" USING btree ("contact_link_edge_id");--> statement-breakpoint
CREATE UNIQUE INDEX "visitor_sessions_visitor_key_idx" ON "visitor_sessions" USING btree ("contact_link_edge_id","visitor_public_key");--> statement-breakpoint
CREATE INDEX "visitor_sessions_conversation_idx" ON "visitor_sessions" USING btree ("conversation_id");