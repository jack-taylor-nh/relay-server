/**
 * Inbound DM Handler
 * 
 * Processes Discord DMs and forwards them to Relay users
 * 
 * Flow:
 * 1. Discord user DMs bot: "/relay @handle message" or "/relay handle message"
 * 2. Bot parses command to extract target Relay edge and message
 * 3. Bot looks up target Relay edge by handle
 * 4. Bot encrypts message with target's edge X25519 public key
 * 5. Bot forwards to Relay API for storage
 * 
 * The Discord user does NOT need a Relay account - they're messaging
 * a Relay user through the bridge.
 */

import { Message, ChatInputCommandInteraction } from 'discord.js';
import { lookupEdgeByHandle, forwardToApi, updateConversationMessageId, lookupExistingConversation } from '../api.js';
import { encryptPayload, hashDiscordId, encryptForWorkerStorage } from '../crypto.js';

// Command format: /relay &handle message OR /relay handle message
const RELAY_COMMAND_REGEX = /^\/relay\s+[&@]?([a-zA-Z0-9_-]+)\s+(.+)$/s;

// Help message
const HELP_MESSAGE = `**Relay Bot** - Send messages to Relay users

**Usage:**
\`/relay &handle Your message here\`
\`/relay handle Your message here\`

**Example:**
\`/relay &alice Hey, can we chat?\`

The Relay user will receive your message and can reply back to you here.

Learn more: https://userelay.org`;

/**
 * Handle an inbound Discord DM
 */
export async function handleInboundDM(message: Message): Promise<void> {
  const content = message.content.trim();
  const discordUserId = message.author.id;
  const discordUsername = message.author.tag;
  
  // Check for /relay command
  const match = content.match(RELAY_COMMAND_REGEX);
  
  if (!match) {
    // Not a relay command - show help
    if (content.toLowerCase().startsWith('/relay') || content.toLowerCase() === 'help') {
      await message.reply(HELP_MESSAGE);
    } else {
      await message.reply({
        content: `👋 Hi! To message a Relay user, use:\n\`/relay &handle Your message\`\n\nType \`help\` for more info.`,
      });
    }
    return;
  }
  
  const targetHandle = match[1].toLowerCase();
  const messageContent = match[2].trim();
  
  if (!messageContent) {
    await message.reply('❌ Please include a message. Example: `/relay &handle Hello!`');
    return;
  }
  
  console.log(`📥 Discord user ${discordUsername} → Relay @${targetHandle}: "${messageContent.substring(0, 50)}..."`);
  
  // Look up target Relay edge by handle
  const edgeInfo = await lookupEdgeByHandle(targetHandle);
  
  if (!edgeInfo) {
    await message.reply(`❌ Relay user \`&${targetHandle}\` not found. Check the handle and try again.`);
    return;
  }
  
  // Hash sender's Discord ID for conversation matching (like email's fromAddressHash)
  const senderHash = await hashDiscordId(discordUserId);
  
  // Check if conversation already exists with this Relay handle
  const existingConversation = await lookupExistingConversation(senderHash, edgeInfo.id);
  
  // Encrypt Discord user ID for reply routing (only worker can decrypt)
  const encryptedDiscordId = encryptForWorkerStorage(discordUserId);
  
  // Build message payload (will be encrypted for the Relay user)
  const messagePayload = {
    content: messageContent,
    senderDisplayName: message.author.displayName,
    messageId: message.id,
    timestamp: message.createdAt.toISOString(),
  };
  
  // Build counterparty metadata for conversation list display
  const counterpartyMetadata = {
    counterpartyDisplayName: message.author.displayName,
    platform: 'discord',
  };
  
  // Encrypt payload with target Relay edge's X25519 public key (zero-knowledge)
  const encryptedPayload = encryptPayload(messagePayload, edgeInfo.x25519PublicKey);
  const encryptedMetadata = encryptPayload(counterpartyMetadata, edgeInfo.x25519PublicKey);
  
  const timestamp = new Date().toLocaleTimeString('en-US', { 
    hour: 'numeric', 
    minute: '2-digit',
    hour12: true 
  });
  
  // Forward to Relay API
  try {
    const apiResult = await forwardToApi({
      edgeId: edgeInfo.id,
      senderHash,
      encryptedRecipientId: encryptedDiscordId,
      encryptedPayload,
      encryptedMetadata,
      discordMessageId: message.id,
      receivedAt: new Date().toISOString(),
    });
    
    // Get the conversation ID from API result (works for both new and existing)
    const conversationId = apiResult?.conversationId || existingConversation?.conversationId;
    
    // React to confirm
    await message.react('✅');
    
    // If existing conversation with a conversation message, edit it
    if (existingConversation?.conversationMessageId) {
      try {
        // Fetch the conversation message from this DM channel
        const conversationMessage = await message.channel.messages.fetch(existingConversation.conversationMessageId);
        
        // Append the new message to the existing conversation
        const existingContent = conversationMessage.content;
        const insertPoint = existingContent.lastIndexOf('\n━━━━━━━━━━━━━━━━━━━━\n');
        
        let newContent: string;
        if (insertPoint !== -1) {
          const beforeFooter = existingContent.substring(0, insertPoint);
          const footer = existingContent.substring(insertPoint);
          newContent = `${beforeFooter}\n**You** _(${timestamp})_:\n${messageContent}\n${footer}`;
        } else {
          newContent = `${existingContent}\n\n**You** _(${timestamp})_:\n${messageContent}`;
        }
        
        // Truncate if too long
        if (newContent.length > 1900) {
          const lines = newContent.split('\n');
          const header = lines.slice(0, 3).join('\n');
          const footer = lines.slice(-3).join('\n');
          const middle = lines.slice(3, -3);
          while (middle.length > 0 && (header + '\n' + middle.join('\n') + '\n' + footer).length > 1800) {
            middle.shift();
          }
          newContent = header + '\n_(earlier messages truncated)_\n\n' + middle.join('\n') + '\n' + footer;
        }
        
        // Edit the conversation message
        await conversationMessage.edit(newContent);
        
        console.log(`✅ Appended to existing conversation message ${existingConversation.conversationMessageId}`);
        return;
        
      } catch (editError) {
        console.warn('Could not edit existing conversation message:', editError);
        // Fall through to create new conversation message
      }
    }
    
    // Create the conversation message with proper formatting
    let conversationContent = `💬 **Conversation with &${targetHandle}**\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n\n`;
    conversationContent += `**You** _(${timestamp})_:\n${messageContent}\n\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n`;
    conversationContent += `_Reply with_ \`/relay &${targetHandle} your message\``;
    
    const replyMessage = await message.reply({
      content: conversationContent,
    });
    
    // Store the conversation message ID for future edits
    if (replyMessage) {
      try {
        await updateConversationMessageId(conversationId, replyMessage.id);
      } catch (updateError) {
        console.warn('Could not update conversation message ID:', updateError);
      }
    }
    
    console.log(`✅ Created new conversation message for ${targetHandle}`);
  } catch (error) {
    console.error('Failed to forward message:', error);
    await message.reply('❌ Failed to send message. Please try again later.');
  }
}

/**
 * Handle the /relay slash command
 * This is the preferred method as it shows up as a real Discord command
 * 
 * If a conversation already exists with this Relay handle, we edit the existing
 * conversation message. Otherwise, we create a new one.
 */
export async function handleSlashCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  const discordUserId = interaction.user.id;
  const discordUsername = interaction.user.tag;
  const discordDisplayName = interaction.user.displayName;
  
  // Get command options
  const handleInput = interaction.options.getString('handle', true);
  const messageContent = interaction.options.getString('message', true);
  
  // Clean the handle (remove & or @ if present)
  const targetHandle = handleInput.replace(/^[&@]/, '').toLowerCase();
  
  console.log(`📥 /relay from ${discordUsername} → &${targetHandle}: "${messageContent.substring(0, 50)}..."`);
  
  // Defer reply - this creates a new message in the DM
  await interaction.deferReply();
  
  // Look up target Relay edge by handle
  const edgeInfo = await lookupEdgeByHandle(targetHandle);
  
  if (!edgeInfo) {
    await interaction.editReply(`❌ Relay user \`&${targetHandle}\` not found. Check the handle and try again.`);
    return;
  }
  
  // Hash sender's Discord ID for conversation matching (like email's fromAddressHash)
  const senderHash = await hashDiscordId(discordUserId);
  
  // Check if conversation already exists with this Relay handle
  const existingConversation = await lookupExistingConversation(senderHash, edgeInfo.id);
  
  // Encrypt Discord user ID for reply routing (only worker can decrypt)
  const encryptedDiscordId = encryptForWorkerStorage(discordUserId);
  
  // Build message payload (will be encrypted for the Relay user)
  const messagePayload = {
    content: messageContent,
    senderDisplayName: discordDisplayName,
    messageId: interaction.id,
    timestamp: new Date().toISOString(),
  };
  
  // Build counterparty metadata for conversation list display
  const counterpartyMetadata = {
    counterpartyDisplayName: discordDisplayName,
    platform: 'discord',
  };
  
  // Encrypt payload with target Relay edge's X25519 public key (zero-knowledge)
  const encryptedPayload = encryptPayload(messagePayload, edgeInfo.x25519PublicKey);
  const encryptedMetadata = encryptPayload(counterpartyMetadata, edgeInfo.x25519PublicKey);
  
  const timestamp = new Date().toLocaleTimeString('en-US', { 
    hour: 'numeric', 
    minute: '2-digit',
    hour12: true 
  });
  
  try {
    // Forward to Relay API
    const apiResult = await forwardToApi({
      edgeId: edgeInfo.id,
      senderHash,
      encryptedRecipientId: encryptedDiscordId,
      encryptedPayload,
      encryptedMetadata,
      discordMessageId: interaction.id,
      receivedAt: new Date().toISOString(),
    });
    
    // Get the conversation ID from API result (works for both new and existing)
    const conversationId = apiResult?.conversationId || existingConversation?.conversationId;
    
    // If existing conversation with a conversation message, edit it
    if (existingConversation?.conversationMessageId) {
      try {
        // Fetch the DM channel
        const user = await interaction.client.users.fetch(discordUserId);
        const dmChannel = await user.createDM();
        const conversationMessage = await dmChannel.messages.fetch(existingConversation.conversationMessageId);
        
        // Append the new message to the existing conversation
        const existingContent = conversationMessage.content;
        const insertPoint = existingContent.lastIndexOf('\n━━━━━━━━━━━━━━━━━━━━\n');
        
        let newContent: string;
        if (insertPoint !== -1) {
          const beforeFooter = existingContent.substring(0, insertPoint);
          const footer = existingContent.substring(insertPoint);
          newContent = `${beforeFooter}\n**You** _(${timestamp})_:\n${messageContent}\n${footer}`;
        } else {
          newContent = `${existingContent}\n\n**You** _(${timestamp})_:\n${messageContent}`;
        }
        
        // Truncate if too long
        if (newContent.length > 1900) {
          const lines = newContent.split('\n');
          const header = lines.slice(0, 3).join('\n');
          const footer = lines.slice(-3).join('\n');
          const middle = lines.slice(3, -3);
          while (middle.length > 0 && (header + '\n' + middle.join('\n') + '\n' + footer).length > 1800) {
            middle.shift();
          }
          newContent = header + '\n_(earlier messages truncated)_\n\n' + middle.join('\n') + '\n' + footer;
        }
        
        // Edit the conversation message
        await conversationMessage.edit(newContent);
        
        // Delete the deferred reply (we don't need a new message)
        await interaction.deleteReply();
        
        console.log(`✅ Appended to existing conversation message ${existingConversation.conversationMessageId}`);
        return;
        
      } catch (editError) {
        console.warn('Could not edit existing conversation message:', editError);
        // Fall through to create new conversation message
      }
    }
    
    // Create new conversation message
    let conversationContent = `💬 **Conversation with &${targetHandle}**\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n\n`;
    conversationContent += `**You** _(${timestamp})_:\n${messageContent}\n\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n`;
    conversationContent += `_Reply with_ \`/relay &${targetHandle} your message\``;
    
    const replyMessage = await interaction.editReply(conversationContent);
    
    // Store the conversation message ID for future edits
    if (replyMessage && 'id' in replyMessage) {
      try {
        await updateConversationMessageId(conversationId, replyMessage.id);
      } catch (updateError) {
        console.warn('Could not update conversation message ID:', updateError);
      }
    }
    
    console.log(`✅ Created new conversation message for ${targetHandle}`);
    
  } catch (error) {
    console.error('Failed to forward message:', error);
    await interaction.editReply('❌ Failed to send message. Please try again later.');
  }
}

