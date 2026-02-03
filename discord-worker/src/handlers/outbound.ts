/**
 * Outbound Message Handler
 * 
 * Sends Discord DMs on behalf of Relay users using Components V2:
 * 
 * 1. When Discord user first messages via /relay, we create a Container-based
 *    "conversation message" with branded styling
 * 2. When Relay user replies, we EDIT the conversation message to append the reply
 * 3. We also send a brief notification DM that auto-deletes (to trigger Discord notification)
 * 
 * This creates a pseudo-thread experience where the conversation lives in one
 * richly-formatted, editable message.
 */

import { Client, User } from 'discord.js';
import { decryptForWorker } from '../crypto.js';
import {
  buildConversationComponents,
  buildNotificationContent,
  formatDiscordTimestamp,
  MESSAGE_FLAGS,
  MessageEntry,
  ConversationContext,
  ComponentType,
} from './components.js';

// How long to show the notification before deleting (ms)
const NOTIFICATION_DELETE_DELAY = 3000;

// Maximum messages to keep in conversation (to avoid Discord limits)
const MAX_CONVERSATION_MESSAGES = 10;

export interface SendMessageRequest {
  conversationId: string;
  content: string;
  encryptedRecipientId: string;  // Encrypted Discord user ID (worker decrypts)
  edgeAddress: string;           // Sender's edge address (handle)
  conversationMessageId?: string; // Bot's conversation message to edit
}

export interface SendMessageResponse {
  success: boolean;
  messageId?: string;
  conversationMessageId?: string;  // The conversation message ID (may be new or existing)
  error?: string;
}

/**
 * Parse messages from legacy text format (for backwards compatibility)
 */
function parseExistingMessagesFromLegacy(content: string, targetHandle: string): MessageEntry[] {
  const messages: MessageEntry[] = [];
  
  // Match: **SenderName** _(timestamp)_:\nMessage content
  const regex = /\*\*(.+?)\*\* _\((.+?)\)_:\n([\s\S]+?)(?=\n\n\*\*|━━━━|$)/g;
  let match;
  
  while ((match = regex.exec(content)) !== null) {
    const senderName = match[1];
    const timestamp = match[2];
    const msgContent = match[3].trim();
    
    // Determine if from Relay or Discord based on sender name
    const isFromRelay = senderName.startsWith('&') || senderName !== 'You';
    
    messages.push({
      from: isFromRelay ? 'relay' : 'discord',
      senderName: isFromRelay ? senderName : 'You',
      content: msgContent,
      timestamp: timestamp.startsWith('<t:') ? timestamp : `<t:${Math.floor(Date.now() / 1000)}:t>`,
    });
  }
  
  return messages;
}

/**
 * Send a message with Components V2 via Discord REST API
 */
async function sendMessageWithComponentsV2(channelId: string, components: any[]): Promise<string> {
  const response = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      flags: MESSAGE_FLAGS.IS_COMPONENTS_V2,
      components,
    }),
  });
  
  if (!response.ok) {
    const error = await response.text();
    console.error('Discord API error:', error);
    throw new Error(`Failed to send message: ${response.status}`);
  }
  
  const data = await response.json() as { id: string };
  return data.id;
}

/**
 * Edit a message with Components V2 via Discord REST API
 */
async function editMessageWithComponentsV2(
  channelId: string,
  messageId: string,
  components: any[]
): Promise<void> {
  const response = await fetch(
    `https://discord.com/api/v10/channels/${channelId}/messages/${messageId}`,
    {
      method: 'PATCH',
      headers: {
        'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        flags: MESSAGE_FLAGS.IS_COMPONENTS_V2,
        components,
      }),
    }
  );
  
  if (!response.ok) {
    const error = await response.text();
    console.error('Discord API error:', error);
    throw new Error(`Failed to edit message: ${response.status}`);
  }
}

/**
 * Send a DM to a Discord user, using the Components V2 conversation pattern
 */
export async function handleOutboundDM(
  client: Client,
  request: SendMessageRequest
): Promise<SendMessageResponse> {
  try {
    // Decrypt the Discord user ID (only worker can do this)
    let recipientDiscordId: string;
    try {
      recipientDiscordId = decryptForWorker(request.encryptedRecipientId);
    } catch (error) {
      console.error('Failed to decrypt recipient Discord ID:', error);
      return {
        success: false,
        error: 'Failed to decrypt recipient ID',
      };
    }
    
    console.log(`📤 Sending DM to Discord user ${recipientDiscordId}`);
    
    // Fetch Discord user
    let user: User;
    try {
      user = await client.users.fetch(recipientDiscordId);
    } catch (error) {
      console.error(`Failed to fetch Discord user ${recipientDiscordId}:`, error);
      return {
        success: false,
        error: 'Discord user not found',
      };
    }
    
    try {
      const dmChannel = await user.createDM();
      const timestamp = formatDiscordTimestamp();
      
      // New message from Relay user
      const newMessage: MessageEntry = {
        from: 'relay',
        senderName: `&${request.edgeAddress}`,
        content: request.content,
        timestamp,
      };
      
      // Try to edit the existing conversation message
      if (request.conversationMessageId) {
        try {
          const conversationMessage = await dmChannel.messages.fetch(request.conversationMessageId);
          
          // Parse existing messages - check if legacy format or new format
          let existingMessages: MessageEntry[] = [];
          
          // If the message has content (legacy format), parse from there
          if (conversationMessage.content && conversationMessage.content.includes('━━━━')) {
            existingMessages = parseExistingMessagesFromLegacy(conversationMessage.content, request.edgeAddress);
          }
          // Note: For Components V2 messages, we'd need to fetch via REST API
          // For now, we track messages by accumulating them
          
          // Add new message
          existingMessages.push(newMessage);
          
          // Truncate if too many
          if (existingMessages.length > MAX_CONVERSATION_MESSAGES) {
            existingMessages = existingMessages.slice(-MAX_CONVERSATION_MESSAGES);
          }
          
          // Build updated Components V2 message
          const context: ConversationContext = {
            targetHandle: request.edgeAddress,
            messages: existingMessages,
            securityLevel: 'relayed',
          };
          
          // Edit with new components via REST API
          await editMessageWithComponentsV2(
            dmChannel.id,
            request.conversationMessageId,
            buildConversationComponents(context)
          );
          
          console.log(`✏️ Updated conversation message ${request.conversationMessageId}`);
          
          // Send a notification that auto-deletes (to trigger Discord notification)
          const notification = await dmChannel.send({
            content: buildNotificationContent(request.edgeAddress),
          });
          
          // Delete the notification after a delay
          setTimeout(async () => {
            try {
              await notification.delete();
              console.log(`🗑️ Deleted notification ${notification.id}`);
            } catch (deleteError) {
              console.warn('Could not delete notification:', deleteError);
            }
          }, NOTIFICATION_DELETE_DELAY);
          
          return {
            success: true,
            messageId: notification.id,
            conversationMessageId: request.conversationMessageId,
          };
          
        } catch (editError) {
          console.warn(`Could not edit conversation message ${request.conversationMessageId}:`, editError);
          // Fall through to create new conversation message
        }
      }
      
      // No existing conversation message or couldn't edit - create new Components V2 message
      const context: ConversationContext = {
        targetHandle: request.edgeAddress,
        messages: [newMessage],
        securityLevel: 'relayed',
      };
      
      // Send Components V2 message via REST API
      const conversationMessageId = await sendMessageWithComponentsV2(
        dmChannel.id,
        buildConversationComponents(context)
      );
      
      console.log(`✅ Created new conversation message ${conversationMessageId} for ${user.tag}`);
      
      return {
        success: true,
        messageId: conversationMessageId,
        conversationMessageId,
      };
      
    } catch (error) {
      console.error(`Failed to send DM to ${user.tag}:`, error);
      return {
        success: false,
        error: 'Failed to send DM - user may have DMs disabled',
      };
    }
  } catch (error) {
    console.error('Outbound DM error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

