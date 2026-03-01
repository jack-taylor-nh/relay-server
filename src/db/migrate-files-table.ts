/**
 * Add files table to existing database
 * Run this migration to add file storage support
 */

import 'dotenv/config';
import postgres from 'postgres';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is required');
}

const sql = postgres(connectionString, { max: 1 });

async function migrateFilesTable() {
  try {
    console.log('🚀 Adding files table to database...');
    console.log('📍 Database:', connectionString.split('@')[1]?.split('?')[0] || 'Unknown');
    
    // Check if files table exists
    const tableExists = await sql`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'files'
      );
    `;
    
    if (tableExists[0].exists) {
      console.log('✅ files table already exists, skipping creation');
      return;
    }
    
    console.log('📄 Creating files table...');
    
    // Create files table
    await sql`
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
    `;
    
    console.log('🔗 Adding foreign key constraints...');
    
    // Add foreign keys
    await sql`
      ALTER TABLE "files" 
      ADD CONSTRAINT "files_conversation_id_conversations_id_fk" 
      FOREIGN KEY ("conversation_id") 
      REFERENCES "public"."conversations"("id") 
      ON DELETE no action ON UPDATE no action;
    `;
    
    await sql`
      ALTER TABLE "files" 
      ADD CONSTRAINT "files_message_id_messages_id_fk" 
      FOREIGN KEY ("message_id") 
      REFERENCES "public"."messages"("id") 
      ON DELETE no action ON UPDATE no action;
    `;
    
    await sql`
      ALTER TABLE "files" 
      ADD CONSTRAINT "files_uploader_edge_id_edges_id_fk" 
      FOREIGN KEY ("uploader_edge_id") 
      REFERENCES "public"."edges"("id") 
      ON DELETE no action ON UPDATE no action;
    `;
    
    console.log('📑 Creating indexes...');
    
    // Create indexes
    await sql`CREATE INDEX "files_conversation_idx" ON "files" USING btree ("conversation_id");`;
    await sql`CREATE INDEX "files_message_idx" ON "files" USING btree ("message_id");`;
    await sql`CREATE INDEX "files_uploader_query_key_idx" ON "files" USING btree ("uploader_query_key");`;
    await sql`CREATE INDEX "files_status_idx" ON "files" USING btree ("status");`;
    await sql`CREATE UNIQUE INDEX "files_storage_key_idx" ON "files" USING btree ("storage_key");`;
    
    console.log('✨ files table created successfully!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Add R2 credentials to Railway environment variables');
    console.log('2. Deploy the updated server code');
    console.log('3. Test file upload from client');
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

migrateFilesTable();
