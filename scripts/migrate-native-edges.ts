/**
 * Migration script: Create native edges for existing handles
 * Run this once on production to ensure all handles have native edges
 */

import { db } from '../src/db/index.js';
import { handles, edges } from '../src/db/schema.js';
import { eq } from 'drizzle-orm';
import { randomUUID } from 'crypto';

async function migrateNativeEdges() {
  console.log('🔍 Checking for handles without native edges...');
  
  const allHandles = await db.select().from(handles);
  console.log(`Found ${allHandles.length} total handles`);
  
  let created = 0;
  let existing = 0;
  
  for (const handle of allHandles) {
    // Check if native edge exists
    const nativeEdge = await db
      .select()
      .from(edges)
      .where(eq(edges.handleId, handle.id))
      .limit(1);
    
    if (nativeEdge.length > 0 && nativeEdge[0].isNative) {
      existing++;
      console.log(`✓ Handle &${handle.handle} already has native edge`);
      continue;
    }
    
    // Create native edge
    const edgeId = randomUUID();
    await db.insert(edges).values({
      id: edgeId,
      identityId: handle.identityId,
      handleId: handle.id,
      type: 'native',
      bridgeType: 'native',
      isNative: true,
      address: handle.handle,
      status: 'active',
      securityLevel: 'e2ee',
      metadata: {},
      createdAt: handle.createdAt,
      messageCount: 0,
    });
    
    created++;
    console.log(`✅ Created native edge for &${handle.handle}`);
  }
  
  console.log('\n📊 Migration complete:');
  console.log(`  - Native edges already existed: ${existing}`);
  console.log(`  - Native edges created: ${created}`);
  console.log(`  - Total handles: ${allHandles.length}`);
}

migrateNativeEdges()
  .then(() => {
    console.log('\n✨ Migration successful!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Migration failed:', error);
    process.exit(1);
  });
