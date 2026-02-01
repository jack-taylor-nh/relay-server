/**
 * Run data migration: Convert handles to pure edge model
 */

import postgres from 'postgres';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error('❌ DATABASE_URL environment variable is required');
  process.exit(1);
}

const sql = postgres(databaseUrl);

async function runMigration() {
  console.log('🔄 Running handle-to-edge data migration...\n');

  try {
    // Read and execute the migration SQL
    const migrationSql = readFileSync(
      join(__dirname, '../drizzle/0002_migrate_handles_to_edges.sql'),
      'utf-8'
    );

    // Execute the migration
    await sql.unsafe(migrationSql);

    console.log('✅ Migration completed successfully!\n');

    // Show statistics
    const [stats] = await sql`
      SELECT 
        (SELECT COUNT(*) FROM edges WHERE is_native = true) as native_edges,
        (SELECT COUNT(*) FROM handles) as total_handles,
        (SELECT COUNT(*) FROM edges WHERE is_native = true AND metadata->>'handle' IS NOT NULL) as edges_with_metadata
    `;

    console.log('📊 Statistics:');
    console.log(`  Native edges: ${stats.native_edges}`);
    console.log(`  Total handles: ${stats.total_handles}`);
    console.log(`  Edges with handle metadata: ${stats.edges_with_metadata}`);

  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

runMigration();
