/**
 * Run migration 0014: Add redemption tables
 */

import postgres from 'postgres';
import { readFileSync } from 'fs';
import { join } from 'path';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.error('❌ DATABASE_URL environment variable is required');
  process.exit(1);
}

const sql = postgres(connectionString, { max: 1 });

async function migrate() {
  try {
    console.log('🚀 Running migration 0014_add_redemption_tables...');
    
    const filePath = join(process.cwd(), 'drizzle', '0014_add_redemption_tables.sql');
    const migration = readFileSync(filePath, 'utf-8');
    
    await sql.unsafe(migration);
    console.log('✅ Migration 0014 applied successfully!');
    
    // Show statistics
    console.log('\n📊 Statistics:');
    const [codeStats] = await sql`SELECT COUNT(*) as count FROM redemption_codes`;
    const [receiptStats] = await sql`SELECT COUNT(*) as count FROM redemption_receipts`;
    console.log(`  Redemption codes: ${codeStats.count}`);
    console.log(`  Redemption receipts: ${receiptStats.count}`);
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

migrate();
