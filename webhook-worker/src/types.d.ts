/**
 * Webhook Payload Schema
 *
 * Strict schema enforced for all incoming webhooks
 */
export interface WebhookPayload {
    /** REQUIRED: Sender alias (e.g., "github-ci", "stripe-billing") */
    sender: string;
    /** REQUIRED: Notification title */
    title: string;
    /** REQUIRED: Message content (plaintext) */
    body: string;
    /** OPTIONAL: Structured JSON data for future automation */
    data?: any;
    /** OPTIONAL: ISO 8601 timestamp */
    timestamp?: string;
}
/**
 * Validate webhook payload
 */
export declare function validatePayload(payload: any): {
    valid: boolean;
    error?: string;
    data?: WebhookPayload;
};
/**
 * Edge info from API
 */
export interface EdgeInfo {
    edgeId: string;
    type: string;
    status: string;
    securityLevel: string;
    x25519PublicKey: string;
    authToken?: string;
}
//# sourceMappingURL=types.d.ts.map