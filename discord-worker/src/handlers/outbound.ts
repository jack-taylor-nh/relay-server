/**
 * Outbound Message Handler
 * 
 * Sends Discord DMs on behalf of Relay users
 * 
 * Flow:
 * 1. Relay API calls /send endpoint with ENCRYPTED recipient Discord ID
 * 2. Bot decrypts the ID using its private key
 * 3. Bot sends DM to Discord user
 * 
 * Note: The encrypted Discord ID comes from the server, which stored it
 * when the inbound message arrived. Only the worker can decrypt it.
 */

import { Client, User, Message } from 'discord.js';
import { decryptForWorker } from '../crypto.js';

export interface SendMessageRequest {
  conversationId: string;
  content: string;
  encryptedRecipientId: string;  // Encrypted Discord user ID (worker decrypts)
  edgeAddress: string;           // Sender's edge address (handle)
  replyToMessageId?: string;     // Discord message ID to reply to (for threading)
}

export interface SendMessageResponse {
  success: boolean;
  messageId?: string;
  error?: string;
}

/**
 * Send a DM to a Discord user
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
    
    // Format the message with sender context
    // Include which Relay handle is responding
    const formattedContent = `**&${request.edgeAddress}** replied:\n\n${request.content}`;
    
    // Send DM - try to reply to original message for threading
    try {
      const dmChannel = await user.createDM();
      
      let sentMessage: Message;
      
      // If we have a message to reply to, use Discord's reply feature
      if (request.replyToMessageId) {
        try {
          const originalMessage = await dmChannel.messages.fetch(request.replyToMessageId);
          sentMessage = await originalMessage.reply({
            content: formattedContent,
          });
          console.log(`✅ Reply sent to ${user.tag}, replying to message ${request.replyToMessageId}`);
        } catch (replyError) {
          // Original message not found or can't reply - send as new DM
          console.warn(`Could not reply to message ${request.replyToMessageId}, sending as new DM:`, replyError);
          sentMessage = await dmChannel.send({
            content: formattedContent,
          });
        }
      } else {
        // No message to reply to - send as new DM
        sentMessage = await dmChannel.send({
          content: formattedContent,
        });
      }
      
      console.log(`✅ DM sent to ${user.tag}, message ID: ${sentMessage.id}`);
      
      return {
        success: true,
        messageId: sentMessage.id,
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
