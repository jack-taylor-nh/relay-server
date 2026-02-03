/**
 * Outbound Message Handler
 * 
 * Sends Discord DMs on behalf of Relay users using a "conversation message" pattern:
 * 
 * 1. When Discord user first messages via /relay, we send a confirmation that becomes 
 *    the "conversation message"
 * 2. When Relay user replies, we EDIT the conversation message to append the reply
 * 3. We also send a brief notification DM that auto-deletes (to trigger Discord notification)
 * 
 * This creates a pseudo-thread experience where the conversation lives in one editable message.
 */

import { Client, User, Message, DMChannel } from 'discord.js';
import { decryptForWorker } from '../crypto.js';

// How long to show the notification before deleting (ms)
const NOTIFICATION_DELETE_DELAY = 3000;

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
 * Format a timestamp for display using Discord's native format
 * This renders in the user's local timezone automatically
 */
function formatTimestamp(): string {
  const unixTimestamp = Math.floor(Date.now() / 1000);
  return `<t:${unixTimestamp}:t>`; // :t = short time format
}

/**
 * Build the initial conversation message content
 */
function buildConversationContent(
  edgeAddress: string,
  messages: Array<{ from: 'relay' | 'discord'; content: string; time: string }>
): string {
  let content = `💬 **Conversation with &${edgeAddress}**\n`;
  content += `━━━━━━━━━━━━━━━━━━━━\n\n`;
  
  for (const msg of messages) {
    if (msg.from === 'relay') {
      content += `**&${edgeAddress}** _(${msg.time})_:\n${msg.content}\n\n`;
    } else {
      content += `**You** _(${msg.time})_:\n${msg.content}\n\n`;
    }
  }
  
  content += `━━━━━━━━━━━━━━━━━━━━\n`;
  content += `_Reply with_ \`/relay &${edgeAddress} your message\``;
  
  return content;
}

/**
 * Send a DM to a Discord user, using the conversation message pattern
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
      const timestamp = formatTimestamp();
      
      // Try to edit the existing conversation message
      if (request.conversationMessageId) {
        try {
          const conversationMessage = await dmChannel.messages.fetch(request.conversationMessageId);
          
          // Append the new reply to the existing content
          const existingContent = conversationMessage.content;
          const insertPoint = existingContent.lastIndexOf('\n━━━━━━━━━━━━━━━━━━━━\n');
          
          let newContent: string;
          if (insertPoint !== -1) {
            // Insert before the footer
            const beforeFooter = existingContent.substring(0, insertPoint);
            const footer = existingContent.substring(insertPoint);
            newContent = `${beforeFooter}\n**&${request.edgeAddress}** _(${timestamp})_:\n${request.content}\n${footer}`;
          } else {
            // Fallback: just append
            newContent = `${existingContent}\n\n**&${request.edgeAddress}** _(${timestamp})_:\n${request.content}`;
          }
          
          // Discord has a 2000 char limit - truncate old messages if needed
          if (newContent.length > 1900) {
            // Keep header, remove oldest messages, keep recent + footer
            const lines = newContent.split('\n');
            const header = lines.slice(0, 3).join('\n');
            const footer = lines.slice(-3).join('\n');
            const middle = lines.slice(3, -3);
            
            // Remove from the beginning of middle until we fit
            while (middle.length > 0 && (header + '\n' + middle.join('\n') + '\n' + footer).length > 1800) {
              middle.shift();
            }
            
            newContent = header + '\n_(earlier messages truncated)_\n\n' + middle.join('\n') + '\n' + footer;
          }
          
          // Edit the conversation message
          await conversationMessage.edit(newContent);
          console.log(`✏️ Updated conversation message ${request.conversationMessageId}`);
          
          // Send a notification that auto-deletes
          const notification = await dmChannel.send({
            content: `🔔 **New message from &${request.edgeAddress}!** _(check above)_`,
          });
          
          // Delete the notification after a delay
          setTimeout(async () => {
            try {
              await notification.delete();
              console.log(`🗑️ Deleted notification ${notification.id}`);
            } catch (deleteError) {
              // Notification may already be deleted or inaccessible
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
      
      // No existing conversation message or couldn't edit - create new one
      const newConversationContent = buildConversationContent(request.edgeAddress, [
        { from: 'relay', content: request.content, time: timestamp }
      ]);
      
      const conversationMessage = await dmChannel.send({
        content: newConversationContent,
      });
      
      console.log(`✅ Created new conversation message ${conversationMessage.id} for ${user.tag}`);
      
      return {
        success: true,
        messageId: conversationMessage.id,
        conversationMessageId: conversationMessage.id,
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
