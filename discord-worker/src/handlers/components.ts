/**
 * Discord Components V2 Builder
 * 
 * Builds rich, branded message components for Relay pseudo-conversations
 * using Discord's Components V2 system.
 * 
 * Features:
 * - Container with accent color (brand theming)
 * - Thumbnails for participants (Discord vs Relay icons)
 * - Sections for message layout
 * - Action Row with Reply and New Conversation buttons
 */

// Component types for Discord Components V2
export const ComponentType = {
  ACTION_ROW: 1,
  BUTTON: 2,
  STRING_SELECT: 3,
  TEXT_INPUT: 4,
  SECTION: 9,
  TEXT_DISPLAY: 10,
  THUMBNAIL: 11,
  SEPARATOR: 14,
  CONTAINER: 17,
} as const;

// Button styles
export const ButtonStyle = {
  PRIMARY: 1,
  SECONDARY: 2,
  SUCCESS: 3,
  DANGER: 4,
  LINK: 5,
} as const;

// Text input styles
export const TextInputStyle = {
  SHORT: 1,
  PARAGRAPH: 2,
} as const;

// IS_COMPONENTS_V2 flag
export const MESSAGE_FLAGS = {
  IS_COMPONENTS_V2: 1 << 15, // 32768
} as const;

// Brand colors (as decimal RGB values)
export const BRAND_COLORS = {
  RELAY_PRIMARY: 0x6366F1,    // Indigo - main Relay brand
  RELAY_SUCCESS: 0x22C55E,    // Green - for E2EE/secure
  RELAY_WARNING: 0xF59E0B,    // Amber - for warnings
  DISCORD_BLURPLE: 0x5865F2,  // Discord's blurple
} as const;

// Icon URLs - publicly accessible image URLs
// Relay icon is served from our API with CDN caching
// Discord avatars are fetched dynamically per user
export const ICONS = {
  // Relay icon - served from our API with Cloudflare CDN caching
  RELAY: process.env.RELAY_ICON_URL || 'https://api.userelay.org/assets/relay-icon.png',
} as const;

/**
 * Get Discord user avatar URL
 * Discord provides avatar URLs in format: https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png
 * If user has no custom avatar, returns default avatar
 */
export function getDiscordAvatarUrl(userId: string, avatarHash?: string | null): string {
  if (avatarHash) {
    // User has custom avatar
    const extension = avatarHash.startsWith('a_') ? 'gif' : 'png';
    return `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${extension}?size=128`;
  } else {
    // Use default Discord avatar (based on discriminator or user id)
    // Discord uses (userId >> 22) % 6 for the default avatar index for new users
    // or discriminator % 5 for legacy users
    const defaultIndex = (BigInt(userId) >> 22n) % 6n;
    return `https://cdn.discordapp.com/embed/avatars/${defaultIndex}.png`;
  }
}

// Custom IDs for button interactions
export const CUSTOM_IDS = {
  REPLY_BUTTON: 'relay_reply',
  NEW_CONVERSATION_BUTTON: 'relay_new_conversation',
  REPLY_MODAL: 'relay_reply_modal',
  NEW_CONVERSATION_MODAL: 'relay_new_conversation_modal',
  REPLY_MESSAGE_INPUT: 'relay_reply_message',
  NEW_HANDLE_INPUT: 'relay_new_handle',
  NEW_MESSAGE_INPUT: 'relay_new_message',
} as const;

export interface MessageEntry {
  from: 'relay' | 'discord';
  senderName: string;      // Display name
  content: string;
  timestamp: string;       // Discord timestamp format <t:unix:t>
  avatarUrl?: string;      // For Discord users, their actual avatar URL
}

export interface ConversationContext {
  targetHandle: string;           // The Relay handle being messaged
  conversationId?: string;        // For tracking
  messages: MessageEntry[];       // All messages in conversation
  securityLevel?: 'e2ee' | 'relayed';
  discordUserId?: string;         // Discord user ID for avatar
  discordAvatarHash?: string;     // Discord avatar hash
}

/**
 * Build a Components V2 conversation message
 * 
 * Structure:
 * Container (with accent color)
 *   ├── Text Display (header)
 *   ├── Separator
 *   ├── Section (message 1) with Thumbnail
 *   ├── Section (message 2) with Thumbnail
 *   ├── ...
 *   ├── Separator
 *   └── Action Row (Reply, New Conversation buttons)
 */
export function buildConversationComponents(context: ConversationContext): any[] {
  const accentColor = context.securityLevel === 'e2ee' 
    ? BRAND_COLORS.RELAY_SUCCESS 
    : BRAND_COLORS.RELAY_PRIMARY;
  
  // Get Discord user avatar URL (if we have user info)
  const discordAvatarUrl = context.discordUserId 
    ? getDiscordAvatarUrl(context.discordUserId, context.discordAvatarHash)
    : getDiscordAvatarUrl('0'); // Fallback to default
  
  // Build message sections
  const messageSections: any[] = [];
  
  for (const msg of context.messages) {
    const isFromRelay = msg.from === 'relay';
    
    // Determine avatar URL - use message-specific avatar if available, otherwise context avatar
    const avatarUrl = isFromRelay 
      ? ICONS.RELAY 
      : (msg.avatarUrl || discordAvatarUrl);
    
    // Use Text Display for each message (no thumbnail - too large)
    messageSections.push({
      type: ComponentType.TEXT_DISPLAY,
      content: `**${msg.senderName}** ${msg.timestamp}\n${msg.content}`,
    });
    
    // Add small separator between messages (except after last)
    if (msg !== context.messages[context.messages.length - 1]) {
      messageSections.push({
        type: ComponentType.SEPARATOR,
        spacing: 1,
        divider: false,
      });
    }
  }
  
  // Build the full container
  const container: any = {
    type: ComponentType.CONTAINER,
    accent_color: accentColor,
    components: [
      // Header
      {
        type: ComponentType.TEXT_DISPLAY,
        content: `## Conversation with &${context.targetHandle}`,
      },
      // Separator after header
      {
        type: ComponentType.SEPARATOR,
        spacing: 1,
        divider: true,
      },
      // All messages
      ...messageSections,
      // Separator before footer
      {
        type: ComponentType.SEPARATOR,
        spacing: 1,
        divider: true,
      },
      // Action buttons
      {
        type: ComponentType.ACTION_ROW,
        components: [
          {
            type: ComponentType.BUTTON,
            style: ButtonStyle.PRIMARY,
            label: 'Reply',
            custom_id: `${CUSTOM_IDS.REPLY_BUTTON}:${context.targetHandle}`,
          },
          {
            type: ComponentType.BUTTON,
            style: ButtonStyle.SECONDARY,
            label: 'New Conversation',
            custom_id: CUSTOM_IDS.NEW_CONVERSATION_BUTTON,
          },
        ],
      },
    ],
  };
  
  return [container];
}

/**
 * Build a simple notification message (for pinging user about new message)
 * This uses legacy format since it gets deleted quickly
 */
export function buildNotificationContent(senderHandle: string): string {
  return `🔔 **New message from &${senderHandle}!** _(check your conversation above)_`;
}

/**
 * Build the Reply modal
 */
export function buildReplyModal(targetHandle: string): any {
  return {
    title: `Reply to &${targetHandle}`,
    custom_id: `${CUSTOM_IDS.REPLY_MODAL}:${targetHandle}`,
    components: [
      {
        type: ComponentType.ACTION_ROW,
        components: [
          {
            type: ComponentType.TEXT_INPUT,
            custom_id: CUSTOM_IDS.REPLY_MESSAGE_INPUT,
            label: 'Your Message',
            style: TextInputStyle.PARAGRAPH,
            min_length: 1,
            max_length: 2000,
            placeholder: 'Type your reply here...',
            required: true,
          },
        ],
      },
    ],
  };
}

/**
 * Build the New Conversation modal
 */
export function buildNewConversationModal(): any {
  return {
    title: 'Start New Conversation',
    custom_id: CUSTOM_IDS.NEW_CONVERSATION_MODAL,
    components: [
      {
        type: ComponentType.ACTION_ROW,
        components: [
          {
            type: ComponentType.TEXT_INPUT,
            custom_id: CUSTOM_IDS.NEW_HANDLE_INPUT,
            label: 'Relay Handle',
            style: TextInputStyle.SHORT,
            min_length: 1,
            max_length: 50,
            placeholder: 'username (without the & symbol)',
            required: true,
          },
        ],
      },
      {
        type: ComponentType.ACTION_ROW,
        components: [
          {
            type: ComponentType.TEXT_INPUT,
            custom_id: CUSTOM_IDS.NEW_MESSAGE_INPUT,
            label: 'Your Message',
            style: TextInputStyle.PARAGRAPH,
            min_length: 1,
            max_length: 2000,
            placeholder: 'Type your message here...',
            required: true,
          },
        ],
      },
    ],
  };
}

/**
 * Parse the target handle from a custom_id
 * Format: "relay_reply:handle"
 */
export function parseCustomId(customId: string): { action: string; handle?: string } {
  const parts = customId.split(':');
  return {
    action: parts[0],
    handle: parts[1],
  };
}

/**
 * Format timestamp in Discord's native format
 */
export function formatDiscordTimestamp(): string {
  const unixTimestamp = Math.floor(Date.now() / 1000);
  return `<t:${unixTimestamp}:t>`; // :t = short time format
}

/**
 * Build initial conversation for a new message from Discord user
 */
export function buildNewConversation(
  targetHandle: string,
  discordUserDisplayName: string,
  messageContent: string
): { components: any[]; flags: number } {
  const timestamp = formatDiscordTimestamp();
  
  const context: ConversationContext = {
    targetHandle,
    messages: [
      {
        from: 'discord',
        senderName: 'You',
        content: messageContent,
        timestamp,
      },
    ],
    securityLevel: 'relayed',
  };
  
  return {
    components: buildConversationComponents(context),
    flags: MESSAGE_FLAGS.IS_COMPONENTS_V2,
  };
}

/**
 * Parse existing messages from Components V2 message data
 * 
 * Returns array of MessageEntry from the existing conversation.
 * Works with both old Section-based and new TextDisplay-based formats.
 */
export function parseExistingMessages(components: any[]): MessageEntry[] {
  const messages: MessageEntry[] = [];
  
  // Find the container
  const container = components.find(c => c.type === ComponentType.CONTAINER);
  if (!container || !container.components) {
    return messages;
  }
  
  for (const component of container.components) {
    // Handle old Section-based format
    if (component.type === ComponentType.SECTION) {
      const textDisplay = component.components?.find((c: any) => c.type === ComponentType.TEXT_DISPLAY);
      if (textDisplay?.content) {
        const match = textDisplay.content.match(/\*\*(.+?)\*\* (<t:\d+:t>)\n([\s\S]+)/);
        if (match) {
          const isFromRelay = component.accessory?.description === 'Relay User';
          messages.push({
            from: isFromRelay ? 'relay' : 'discord',
            senderName: match[1],
            timestamp: match[2],
            content: match[3],
          });
        }
      }
    }
    // Handle new TextDisplay-based format (no section wrapper)
    else if (component.type === ComponentType.TEXT_DISPLAY) {
      const match = component.content?.match(/\*\*(.+?)\*\* (<t:\d+:t>)\n([\s\S]+)/);
      if (match) {
        // Determine if from Relay based on sender name (starts with &)
        const senderName = match[1];
        const isFromRelay = senderName.startsWith('&');
        messages.push({
          from: isFromRelay ? 'relay' : 'discord',
          senderName,
          timestamp: match[2],
          content: match[3],
        });
      }
    }
  }
  
  return messages;
}

/**
 * Append a message to existing conversation components
 * 
 * Note: With Components V2, we need to rebuild the entire component structure.
 * We'll parse the existing content and add the new message.
 */
export function appendToConversation(
  existingComponents: any[],
  newMessage: MessageEntry,
  targetHandle: string
): { components: any[]; flags: number } {
  // Extract existing messages from components
  const messages = parseExistingMessages(existingComponents);
  
  // Add new message
  messages.push(newMessage);
  
  // Truncate if too many messages (keep most recent)
  const MAX_MESSAGES = 10;
  const truncatedMessages = messages.length > MAX_MESSAGES 
    ? messages.slice(-MAX_MESSAGES)
    : messages;
  
  const context: ConversationContext = {
    targetHandle,
    messages: truncatedMessages,
    securityLevel: 'relayed',
  };
  
  return {
    components: buildConversationComponents(context),
    flags: MESSAGE_FLAGS.IS_COMPONENTS_V2,
  };
}
