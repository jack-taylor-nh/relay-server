/**
 * Database migration runner
 * Applies SQL migration files from the drizzle folder
 */

import 'dotenv/config';
import postgres from 'postgres';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is required');
}

const sql = postgres(connectionString, { max: 1 });

async function migrate() {
  try {
    console.log('🚀 Starting database migration...');
    
    const migrationsDir = join(process.cwd(), 'drizzle');
    const files = readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();
    
    for (const file of files) {
      console.log(`📄 Applying ${file}...`);
      const filePath = join(migrationsDir, file);
      const migration = readFileSync(filePath, 'utf-8');
      
      await sql.unsafe(migration);
      console.log(`✅ ${file} applied successfully`);
    }
    
    console.log('✨ All migrations completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

migrate();
