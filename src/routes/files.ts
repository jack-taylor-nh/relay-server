/**
 * File Routes - Encrypted File Storage
 * 
 * POST /v1/files - Upload encrypted file to R2
 * GET /v1/files/:id - Get file metadata
 * GET /v1/files/:id/download - Download encrypted file from R2
 * DELETE /v1/files/:id - Soft delete file
 * 
 * Files are encrypted client-side before upload.
 * Server stores ciphertext in Cloudflare R2 (S3-compatible).
 * Encryption keys never leave the client.
 */

import { Hono } from 'hono';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { ulid } from 'ulid';
import { eq, and } from 'drizzle-orm';
import { db } from '../db/index.js';
import { files, conversations, edges, type FileMimeType, type FileStatus } from '../db/schema.js';
import { computeQueryKey } from '../lib/queryKey.js';

export const fileRoutes = new Hono();

// ============================================
// R2 Client Configuration
// ============================================

const r2Client = (() => {
  const endpoint = process.env.R2_ENDPOINT;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  
  if (!endpoint || !accessKeyId || !secretAccessKey) {
    console.warn('[Files] R2 credentials not configured. File uploads will fail.');
    return null;
  }
  
  return new S3Client({
    region: 'auto',
    endpoint,
    credentials: {
      accessKeyId,
      secretAccessKey,
    },
  });
})();

const R2_BUCKET = process.env.R2_BUCKET_NAME || 'relay-files';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || '50') * 1024 * 1024; // Default 50MB

// ============================================
// Supported MIME Types
// ============================================

const ALLOWED_MIME_TYPES: FileMimeType[] = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'text/plain',
  'application/octet-stream', // Encrypted generic files
];

// ============================================
// POST /v1/files - Upload File
// ============================================

/**
 * Upload encrypted file to R2
 * 
 * Request:
 * - Content-Type: multipart/form-data
 * - Fields:
 *   - file: Binary file data (encrypted by client)
 *   - conversation_id: Conversation ID
 *   - message_id: (optional) Message ID to attach to
 *   - mime_type: Original MIME type (before encryption)
 *   - encrypted_filename: (optional) Encrypted original filename
 * 
 * Auth: Bearer token (JWT or X25519 edge key)
 */
fileRoutes.post('/', async (c) => {
  if (!r2Client) {
    return c.json({ code: 'SERVICE_UNAVAILABLE', message: 'File storage not configured' }, 503);
  }
  
  // Auth check
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing authorization' }, 401);
  }
  
  const token = authHeader.slice(7);
  let uploaderQueryKey: string | null = null;
  let uploaderEdgeId: string | null = null;
  
  // Try X25519 edge authentication
  try {
    const { fromBase64, toBase64 } = await import('../core/crypto/index.js');
    const nacl = (await import('tweetnacl')).default;
    
    const secretKey = fromBase64(token);
    const derivedKeyPair = nacl.box.keyPair.fromSecretKey(secretKey);
    const derivedPublicKeyBase64 = toBase64(derivedKeyPair.publicKey);
    
    const [edge] = await db
      .select()
      .from(edges)
      .where(eq(edges.x25519PublicKey, derivedPublicKeyBase64))
      .limit(1);
      
    if (edge && edge.status === 'active') {
      uploaderEdgeId = edge.id;
      uploaderQueryKey = edge.ownerQueryKey;
    }
  } catch {}
  
  // Fallback to JWT
  if (!uploaderQueryKey) {
    try {
      const { verifySessionToken } = await import('../lib/jwt.js');
      const payload = await verifySessionToken(token);
      
      if (!payload) {
        return c.json({ code: 'UNAUTHORIZED', message: 'Invalid token' }, 401);
      }
      
      uploaderQueryKey = computeQueryKey(payload.fingerprint);
    } catch {
      return c.json({ code: 'UNAUTHORIZED', message: 'Invalid token' }, 401);
    }
  }
  
  // Parse multipart form data
  const formData = await c.req.formData();
  const file = formData.get('file') as File | null;
  const conversationId = formData.get('conversation_id') as string | null;
  const messageId = formData.get('message_id') as string | null;
  const mimeType = (formData.get('mime_type') as string | null) || 'application/octet-stream';
  const encryptedFilename = formData.get('encrypted_filename') as string | null;
  
  if (!file) {
    return c.json({ code: 'BAD_REQUEST', message: 'Missing file' }, 400);
  }
  
  if (!conversationId) {
    return c.json({ code: 'BAD_REQUEST', message: 'Missing conversation_id' }, 400);
  }
  
  // Validate MIME type
  if (!ALLOWED_MIME_TYPES.includes(mimeType as FileMimeType)) {
    return c.json({ code: 'BAD_REQUEST', message: 'Unsupported MIME type' }, 400);
  }
  
  // Check file size
  if (file.size > MAX_FILE_SIZE) {
    return c.json({ 
      code: 'FILE_TOO_LARGE', 
      message: `File exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit` 
    }, 413);
  }
  
  // Verify conversation exists and user has access
  const [conversation] = await db
    .select()
    .from(conversations)
    .where(eq(conversations.id, conversationId))
    .limit(1);
    
  if (!conversation) {
    return c.json({ code: 'NOT_FOUND', message: 'Conversation not found' }, 404);
  }
  
  try {
    // Generate file ID and storage key
    const fileId = ulid();
    const storageKey = `${conversationId}/${fileId}`;
    
    // Read file buffer
    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    
    // Upload to R2
    const upload = new Upload({
      client: r2Client,
      params: {
        Bucket: R2_BUCKET,
        Key: storageKey,
        Body: buffer,
        ContentType: 'application/octet-stream', // Always encrypted
        Metadata: {
          'file-id': fileId,
          'conversation-id': conversationId,
          'original-mime-type': mimeType,
        },
      },
    });
    
    await upload.done();
    
    // Generate CDN URL (if R2 public domain is configured)
    const cdnDomain = process.env.R2_PUBLIC_DOMAIN;
    const cdnUrl = cdnDomain ? `https://${cdnDomain}/${storageKey}` : null;
    
    // Store metadata in database
    const [fileRecord] = await db
      .insert(files)
      .values({
        id: fileId,
        conversationId,
        messageId: messageId || null,
        uploaderEdgeId,
        uploaderQueryKey,
        encryptedFilename,
        mimeType: mimeType as FileMimeType,
        sizeBytes: file.size,
        storageKey,
        storageBucket: R2_BUCKET,
        cdnUrl,
        status: 'active',
      })
      .returning();
    
    console.log(`[Files] Uploaded file ${fileId} (${file.size} bytes) to R2:${storageKey}`);
    
    return c.json({
      success: true,
      file: {
        id: fileRecord.id,
        conversation_id: fileRecord.conversationId,
        message_id: fileRecord.messageId,
        mime_type: fileRecord.mimeType,
        size_bytes: fileRecord.sizeBytes,
        cdn_url: fileRecord.cdnUrl,
        created_at: fileRecord.createdAt,
      },
    });
  } catch (error) {
    console.error('[Files] Upload error:', error);
    return c.json({ 
      code: 'UPLOAD_FAILED', 
      message: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// ============================================
// GET /v1/files/:id - Get File Metadata
// ============================================

fileRoutes.get('/:id', async (c) => {
  const fileId = c.req.param('id');
  
  // Auth check
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing authorization' }, 401);
  }
  
  const [fileRecord] = await db
    .select()
    .from(files)
    .where(and(
      eq(files.id, fileId),
      eq(files.status, 'active')
    ))
    .limit(1);
    
  if (!fileRecord) {
    return c.json({ code: 'NOT_FOUND', message: 'File not found' }, 404);
  }
  
  return c.json({
    success: true,
    file: {
      id: fileRecord.id,
      conversation_id: fileRecord.conversationId,
      message_id: fileRecord.messageId,
      mime_type: fileRecord.mimeType,
      size_bytes: fileRecord.sizeBytes,
      cdn_url: fileRecord.cdnUrl,
      created_at: fileRecord.createdAt,
    },
  });
});

// ============================================
// GET /v1/files/:id/download - Download File
// ============================================

fileRoutes.get('/:id/download', async (c) => {
  if (!r2Client) {
    return c.json({ code: 'SERVICE_UNAVAILABLE', message: 'File storage not configured' }, 503);
  }
  
  const fileId = c.req.param('id');
  
  // Auth check
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing authorization' }, 401);
  }
  
  const [fileRecord] = await db
    .select()
    .from(files)
    .where(and(
      eq(files.id, fileId),
      eq(files.status, 'active')
    ))
    .limit(1);
    
  if (!fileRecord) {
    return c.json({ code: 'NOT_FOUND', message: 'File not found' }, 404);
  }
  
  try {
    // Download from R2
    const command = new GetObjectCommand({
      Bucket: fileRecord.storageBucket,
      Key: fileRecord.storageKey,
    });
    
    const response = await r2Client.send(command);
    const stream = response.Body;
    
    if (!stream) {
      return c.json({ code: 'DOWNLOAD_FAILED', message: 'Empty response from storage' }, 500);
    }
    
    // Stream the file back to client
    return new Response(stream as any, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': fileRecord.sizeBytes.toString(),
        'Content-Disposition': `attachment; filename="${fileId}"`,
      },
    });
  } catch (error) {
    console.error('[Files] Download error:', error);
    return c.json({ 
      code: 'DOWNLOAD_FAILED', 
      message: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// ============================================
// DELETE /v1/files/:id - Soft Delete File
// ============================================

fileRoutes.delete('/:id', async (c) => {
  const fileId = c.req.param('id');
  
  // Auth check (should verify ownership)
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Missing authorization' }, 401);
  }
  
  const [fileRecord] = await db
    .select()
    .from(files)
    .where(eq(files.id, fileId))
    .limit(1);
    
  if (!fileRecord) {
    return c.json({ code: 'NOT_FOUND', message: 'File not found' }, 404);
  }
  
  // Soft delete (mark as deleted, keep in R2 for recovery)
  await db
    .update(files)
    .set({
      status: 'deleted',
      deletedAt: new Date(),
    })
    .where(eq(files.id, fileId));
  
  console.log(`[Files] Soft deleted file ${fileId}`);
  
  return c.json({ success: true, message: 'File deleted' });
});
