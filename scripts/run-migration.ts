import 'dotenv/config';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { readFileSync } from 'fs';

const connectionString = process.env.DATABASE_URL!;
const client = postgres(connectionString);
const db = drizzle(client);

async function runMigration() {
  const migrationSQL = readFileSync('./drizzle/0002_add_handles_rework.sql', 'utf-8');
  
  console.log('Running handles rework migration...');
  
  try {
    await client.unsafe(migrationSQL);
    console.log('✅ Migration completed successfully');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await client.end();
  }
}

runMigration();
