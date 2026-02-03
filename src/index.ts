/**
 * Relay API - Main Entry Point
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';

import { authRoutes } from './routes/auth.js';
import { identityRoutes } from './routes/identity.js';
import { handleRoutes } from './routes/handles.js';
import { edgeRoutes } from './routes/edges.js';
import { conversationRoutes } from './routes/conversations.js';
import { messageRoutes } from './routes/messages.js';
import { emailRoutes } from './routes/email.js';
import { discordRoutes } from './routes/discord.js';

const app = new Hono();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: (origin) => {
    // Allow Chrome extensions
    if (origin?.startsWith('chrome-extension://')) return origin;
    // Allow localhost for dev
    if (origin?.startsWith('http://localhost')) return origin;
    // Allow our domains
    if (origin?.endsWith('.userelay.org')) return origin;
    if (origin === 'https://userelay.org') return origin;
    // Allow Railway preview URLs
    if (origin?.endsWith('.up.railway.app')) return origin;
    return null;
  },
  credentials: true,
}));

// Health check
app.get('/', (c) => c.json({ 
  name: 'Relay API',
  version: '0.1.0',
  status: 'ok',
}));

app.get('/health', (c) => c.json({ status: 'ok' }));

// API routes
const api = new Hono();

api.route('/auth', authRoutes);
api.route('/identity', identityRoutes);
api.route('/handles', handleRoutes);
api.route('/edge', edgeRoutes);
api.route('/edges', edgeRoutes); // Alias for list
api.route('/conversations', conversationRoutes);
api.route('/messages', messageRoutes);
api.route('/email', emailRoutes);
api.route('/discord', discordRoutes);

app.route('/v1', api);

// Error handling
app.onError((err, c) => {
  console.error('API Error:', err);
  return c.json({ 
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  }, 500);
});

// Not found
app.notFound((c) => c.json({ 
  code: 'NOT_FOUND',
  message: 'Route not found',
}, 404));

// Start server
const port = parseInt(process.env.PORT || '3000', 10);

console.log(`🚀 Relay API starting on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});

export default app;
