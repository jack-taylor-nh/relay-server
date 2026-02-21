/**
 * Run migration 0013 only
 */

import postgres from 'postgres';
import { readFileSync } from 'fs';
import { join } from 'path';

const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:NpkOjwLvHylTiAOWExtBOYDqzSDYBXnU@mainline.proxy.rlwy.net:15720/railway';

const sql = postgres(connectionString, { max: 1 });

async function migrate() {
  try {
    console.log('🚀 Running migration 0013_add_bridge_status_tracking...');
    
    const filePath = join(process.cwd(), 'drizzle', '0013_add_bridge_status_tracking.sql');
    const migration = readFileSync(filePath, 'utf-8');
    
    await sql.unsafe(migration);
    console.log('✅ Migration 0013 applied successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

migrate();
