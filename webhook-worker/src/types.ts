/**
 * Webhook Payload Schema
 * 
 * Flexible schema that accepts any JSON but provides structured
 * display when using our recommended format.
 * 
 * RECOMMENDED FORMAT (for best display):
 * - sender: string (who/what sent this)
 * - title: string (notification title)
 * - body: string (main content, supports markdown)
 * - data: object (additional structured data)
 * 
 * FLEXIBLE FORMAT (for external services like GitHub, Stripe):
 * - Any valid JSON object is accepted
 * - We'll intelligently extract/infer sender, title, body
 * - Original payload preserved in 'raw' field
 */

export interface WebhookPayload {
  /** Sender alias (e.g., "github-ci", "stripe-billing") */
  sender: string;
  
  /** Notification title */
  title: string;
  
  /** Message content (plaintext or markdown) */
  body: string;
  
  /** Structured JSON data */
  data?: any;
  
  /** ISO 8601 timestamp */
  timestamp?: string;
  
  /** Original raw payload (for flexible format) */
  raw?: any;
  
  /** Detected service type (github, stripe, slack, etc.) */
  detectedService?: string;
}

/**
 * Known webhook service signatures for auto-detection
 */
const SERVICE_SIGNATURES: Array<{
  name: string;
  detect: (payload: any, headers: Record<string, string>) => boolean;
  extract: (payload: any, headers: Record<string, string>) => Partial<WebhookPayload>;
}> = [
  {
    name: 'github',
    detect: (payload, headers) => 
      !!headers['x-github-event'] || 
      !!headers['x-github-delivery'] ||
      (payload.repository && payload.sender?.login),
    extract: (payload, headers) => {
      const event = headers['x-github-event'] || 'event';
      const repo = payload.repository?.full_name || payload.repository?.name || 'unknown';
      const actor = payload.sender?.login || payload.pusher?.name || 'GitHub';
      
      // Build a meaningful title based on event type
      let title = `GitHub ${event}`;
      let body = '';
      
      if (event === 'push') {
        const commits = payload.commits?.length || 0;
        const branch = payload.ref?.replace('refs/heads/', '') || 'unknown';
        title = `Push to ${repo}`;
        body = `**${actor}** pushed ${commits} commit${commits !== 1 ? 's' : ''} to \`${branch}\``;
        if (payload.commits?.length > 0) {
          body += '\n\n' + payload.commits.slice(0, 5).map((c: any) => 
            `• \`${c.id?.slice(0, 7)}\` ${c.message?.split('\n')[0] || 'No message'}`
          ).join('\n');
          if (payload.commits.length > 5) {
            body += `\n• ... and ${payload.commits.length - 5} more`;
          }
        }
      } else if (event === 'pull_request') {
        const action = payload.action || 'updated';
        const pr = payload.pull_request;
        title = `PR ${action}: ${pr?.title || 'Unknown'}`;
        body = `**${actor}** ${action} PR #${pr?.number || '?'} in ${repo}`;
      } else if (event === 'issues') {
        const action = payload.action || 'updated';
        const issue = payload.issue;
        title = `Issue ${action}: ${issue?.title || 'Unknown'}`;
        body = `**${actor}** ${action} issue #${issue?.number || '?'} in ${repo}`;
      } else if (event === 'star' || event === 'watch') {
        title = `New star on ${repo}`;
        body = `**${actor}** starred ${repo}`;
      } else {
        body = `Event: ${event} on ${repo}`;
      }
      
      return { sender: 'GitHub', title, body };
    }
  },
  {
    name: 'stripe',
    detect: (payload) => 
      payload.object === 'event' && !!payload.type && !!payload.data?.object,
    extract: (payload) => {
      const eventType = payload.type || 'event';
      const obj = payload.data?.object || {};
      
      let title = eventType.replace(/_/g, ' ').replace(/\./g, ' › ');
      let body = '';
      
      // Format based on event type
      if (eventType.startsWith('payment_intent')) {
        const amount = obj.amount ? `$${(obj.amount / 100).toFixed(2)}` : '';
        title = `Payment ${eventType.split('.').pop()}`;
        body = amount ? `Amount: ${amount} ${obj.currency?.toUpperCase() || ''}` : '';
      } else if (eventType.startsWith('customer')) {
        title = `Customer ${eventType.split('.').pop()}`;
        body = obj.email ? `Email: ${obj.email}` : '';
      } else if (eventType.startsWith('invoice')) {
        const amount = obj.amount_due ? `$${(obj.amount_due / 100).toFixed(2)}` : '';
        title = `Invoice ${eventType.split('.').pop()}`;
        body = amount ? `Amount: ${amount}` : '';
      }
      
      return { sender: 'Stripe', title, body };
    }
  },
  {
    name: 'slack',
    detect: (payload) => 
      !!payload.token && (!!payload.team_id || !!payload.event),
    extract: (payload) => {
      const event = payload.event || {};
      const type = event.type || payload.type || 'message';
      return {
        sender: 'Slack',
        title: `Slack ${type}`,
        body: event.text || payload.text || JSON.stringify(event).slice(0, 200),
      };
    }
  },
  {
    name: 'discord',
    detect: (payload) => 
      !!payload.guild_id || !!payload.channel_id && !!payload.content,
    extract: (payload) => ({
      sender: payload.author?.username || 'Discord',
      title: 'Discord Message',
      body: payload.content || '',
    })
  },
  {
    name: 'linear',
    detect: (payload) => 
      !!payload.organizationId && (!!payload.action || !!payload.type),
    extract: (payload) => {
      const action = payload.action || 'update';
      const data = payload.data || {};
      return {
        sender: 'Linear',
        title: `${payload.type || 'Issue'} ${action}`,
        body: data.title || data.name || '',
      };
    }
  }
];

/**
 * Validate and normalize webhook payload
 * Accepts either our structured format OR any valid JSON
 */
export function validatePayload(
  payload: any, 
  headers: Record<string, string> = {},
  edgeDefaultSender?: string
): { valid: boolean; error?: string; data?: WebhookPayload } {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, error: 'Payload must be a JSON object' };
  }

  // Check total payload size (rough estimate)
  const payloadStr = JSON.stringify(payload);
  if (payloadStr.length > 50000) {
    return { valid: false, error: 'Payload too large (max 50KB)' };
  }

  // Check for explicit sender header
  const headerSender = headers['x-webhook-sender'];
  
  // Try to detect known service
  let detectedService: string | undefined;
  let extractedData: Partial<WebhookPayload> = {};
  
  for (const service of SERVICE_SIGNATURES) {
    if (service.detect(payload, headers)) {
      detectedService = service.name;
      extractedData = service.extract(payload, headers);
      break;
    }
  }

  // Check if payload matches our structured format
  const hasStructuredFormat = 
    typeof payload.sender === 'string' &&
    typeof payload.title === 'string' &&
    typeof payload.body === 'string';

  let normalized: WebhookPayload;

  if (hasStructuredFormat) {
    // Validate our structured format
    if (payload.sender && !/^[\w\s\-_.@]{1,64}$/i.test(payload.sender)) {
      return { valid: false, error: 'Invalid "sender" format (max 64 chars, alphanumeric and basic punctuation)' };
    }
    if (payload.title && payload.title.length > 500) {
      return { valid: false, error: 'Title too long (max 500 characters)' };
    }
    if (payload.body && payload.body.length > 20000) {
      return { valid: false, error: 'Body too long (max 20KB)' };
    }

    normalized = {
      sender: payload.sender,
      title: payload.title,
      body: payload.body,
      data: payload.data,
      timestamp: payload.timestamp,
    };
  } else {
    // Flexible format - extract what we can
    const sender = 
      headerSender ||
      extractedData.sender ||
      payload.sender ||
      payload.user?.name ||
      payload.user?.login ||
      payload.author?.name ||
      payload.from ||
      edgeDefaultSender ||
      detectedService ||
      'Webhook';
    
    const title = 
      extractedData.title ||
      payload.title ||
      payload.subject ||
      payload.name ||
      payload.action ||
      payload.event ||
      payload.type ||
      'Webhook Notification';
    
    const body = 
      extractedData.body ||
      payload.body ||
      payload.message ||
      payload.content ||
      payload.text ||
      payload.description ||
      '';

    normalized = {
      sender: String(sender).slice(0, 64),
      title: String(title).slice(0, 500),
      body: String(body).slice(0, 20000),
      data: payload,  // Store full payload as data
      timestamp: payload.timestamp || payload.created_at || payload.time,
      raw: payload,
      detectedService,
    };
  }

  // Validate timestamp if provided
  if (normalized.timestamp !== undefined) {
    if (typeof normalized.timestamp === 'string' && isNaN(Date.parse(normalized.timestamp))) {
      // Invalid timestamp, just remove it
      normalized.timestamp = undefined;
    }
  }

  return { valid: true, data: normalized };
}

/**
 * Edge info from API
 */
export interface EdgeInfo {
  edgeId: string;
  type: string;
  status: string;
  securityLevel: string;
  x25519PublicKey: string;
  authToken?: string;  // For webhook edges
  defaultSenderName?: string; // Default sender name for flexible webhooks
}
