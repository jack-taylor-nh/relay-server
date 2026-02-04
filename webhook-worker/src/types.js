/**
 * Webhook Payload Schema
 *
 * Strict schema enforced for all incoming webhooks
 */
/**
 * Validate webhook payload
 */
export function validatePayload(payload) {
    if (!payload || typeof payload !== 'object') {
        return { valid: false, error: 'Payload must be a JSON object' };
    }
    // Validate sender
    if (!payload.sender || typeof payload.sender !== 'string') {
        return { valid: false, error: 'Missing or invalid "sender" field (string required)' };
    }
    if (!/^[a-zA-Z0-9-_]{1,64}$/.test(payload.sender)) {
        return { valid: false, error: 'Invalid "sender" format (alphanumeric, hyphens, underscores only, max 64 chars)' };
    }
    // Validate title
    if (!payload.title || typeof payload.title !== 'string') {
        return { valid: false, error: 'Missing or invalid "title" field (string required)' };
    }
    if (payload.title.length > 200) {
        return { valid: false, error: 'Title too long (max 200 characters)' };
    }
    // Validate body
    if (!payload.body || typeof payload.body !== 'string') {
        return { valid: false, error: 'Missing or invalid "body" field (string required)' };
    }
    if (payload.body.length > 10000) {
        return { valid: false, error: 'Body too long (max 10KB)' };
    }
    // Validate timestamp if provided
    if (payload.timestamp !== undefined) {
        if (typeof payload.timestamp !== 'string') {
            return { valid: false, error: 'Invalid "timestamp" field (ISO 8601 string required)' };
        }
        // Verify it's a valid ISO date
        if (isNaN(Date.parse(payload.timestamp))) {
            return { valid: false, error: 'Invalid "timestamp" format (must be ISO 8601)' };
        }
    }
    return {
        valid: true,
        data: {
            sender: payload.sender,
            title: payload.title,
            body: payload.body,
            data: payload.data,
            timestamp: payload.timestamp,
        },
    };
}
//# sourceMappingURL=types.js.map