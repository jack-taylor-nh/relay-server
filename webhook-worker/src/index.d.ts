/**
 * Relay Webhook Worker (Express)
 *
 * Express server that receives webhooks from external services
 * and forwards them to the Relay API for storage
 *
 * Flow:
 * 1. Receive webhook POST at /w/{edgeId} or /w/{edgeId}?auth={token}
 * 2. Verify authToken (from header or query param)
 * 3. Validate payload schema (sender, title, body required)
 * 4. Encrypt payload for user's edge X25519 key
 * 5. Forward to Relay API /v1/webhook/inbound
 */
export {};
//# sourceMappingURL=index.d.ts.map