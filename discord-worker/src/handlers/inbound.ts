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
import { lookupEdgeByHandle, forwardToApi, updateConversationMessageId } from '../api.js';
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
  // This is separate from message content - stored at conversation level
  const counterpartyMetadata = {
    counterpartyDisplayName: message.author.displayName,
    platform: 'discord',
  };
  
  // Encrypt payload with target Relay edge's X25519 public key (zero-knowledge)
  const encryptedPayload = encryptPayload(messagePayload, edgeInfo.x25519PublicKey);
  const encryptedMetadata = encryptPayload(counterpartyMetadata, edgeInfo.x25519PublicKey);
  
  // Forward to Relay API
  // Note: senderHash for matching, encryptedDiscordId for reply routing (only worker can decrypt)
  try {
    const apiResult = await forwardToApi({
      edgeId: edgeInfo.id,
      senderHash,
      encryptedRecipientId: encryptedDiscordId,  // Encrypted for worker's key
      encryptedPayload,
      encryptedMetadata,  // Encrypted counterparty info for conversation list
      discordMessageId: message.id,  // For reply threading
      receivedAt: new Date().toISOString(),
    });
    
    // Create the conversation message with proper formatting
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      hour12: true 
    });
    
    let conversationContent = `💬 **Conversation with &${targetHandle}**\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n\n`;
    conversationContent += `**You** _(${timestamp})_:\n${messageContent}\n\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n`;
    conversationContent += `_Reply with_ \`/relay &${targetHandle} your message\``;
    
    // React to confirm and send the conversation message
    await message.react('✅');
    const replyMessage = await message.reply({
      content: conversationContent,
    });
    
    // Store the conversation message ID for future edits
    if (replyMessage) {
      try {
        await updateConversationMessageId(apiResult?.conversationId, replyMessage.id);
      } catch (updateError) {
        console.warn('Could not update conversation message ID:', updateError);
      }
    }
    
    console.log(`✅ Message forwarded to Relay edge ${edgeInfo.id}, conversation message: ${replyMessage.id}`);
  } catch (error) {
    console.error('Failed to forward message:', error);
    await message.reply('❌ Failed to send message. Please try again later.');
  }
}

/**
 * Handle the /relay slash command
 * This is the preferred method as it shows up as a real Discord command
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
  
  // Defer reply - visible in chat to create conversation thread
  await interaction.deferReply();
  
  // Look up target Relay edge by handle
  const edgeInfo = await lookupEdgeByHandle(targetHandle);
  
  if (!edgeInfo) {
    await interaction.editReply(`❌ Relay user \`&${targetHandle}\` not found. Check the handle and try again.`);
    return;
  }
  
  // Hash sender's Discord ID for conversation matching (like email's fromAddressHash)
  const senderHash = await hashDiscordId(discordUserId);
  
  // Encrypt Discord user ID for reply routing (only worker can decrypt)
  const encryptedDiscordId = encryptForWorkerStorage(discordUserId);
  
  // Build message payload (will be encrypted for the Relay user)
  // Note: The actual Discord ID is NOT in here - it's encrypted separately
  const messagePayload = {
    content: messageContent,
    senderDisplayName: discordDisplayName,
    messageId: interaction.id,
    timestamp: new Date().toISOString(),
  };
  
  // Build counterparty metadata for conversation list display
  // This is separate from message content - stored at conversation level
  const counterpartyMetadata = {
    counterpartyDisplayName: discordDisplayName,
    platform: 'discord',
  };
  
  // Encrypt payload with target Relay edge's X25519 public key (zero-knowledge)
  const encryptedPayload = encryptPayload(messagePayload, edgeInfo.x25519PublicKey);
  const encryptedMetadata = encryptPayload(counterpartyMetadata, edgeInfo.x25519PublicKey);
  
  // Forward to Relay API first to check if conversation exists
  // Note: senderHash for matching, encryptedRecipientId for reply routing (only worker can decrypt)
  try {
    const apiResult = await forwardToApi({
      edgeId: edgeInfo.id,
      senderHash,
      encryptedRecipientId: encryptedDiscordId,  // Encrypted for worker's key
      encryptedPayload,
      encryptedMetadata,  // Encrypted counterparty info for conversation list
      discordMessageId: interaction.id,  // For reply threading (using interaction ID)
      receivedAt: new Date().toISOString(),
    });
    
    // Create the conversation message with proper formatting
    const timestamp = new Date().toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      hour12: true 
    });
    
    let conversationContent = `💬 **Conversation with &${targetHandle}**\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n\n`;
    conversationContent += `**You** _(${timestamp})_:\n${messageContent}\n\n`;
    conversationContent += `━━━━━━━━━━━━━━━━━━━━\n`;
    conversationContent += `_Reply with_ \`/relay &${targetHandle} your message\``;
    
    // Send the conversation message and capture its ID
    const replyMessage = await interaction.editReply(conversationContent);
    
    // Store the conversation message ID for future edits
    // We need to update the API with this message ID
    if (replyMessage && 'id' in replyMessage) {
      try {
        await updateConversationMessageId(apiResult?.conversationId, replyMessage.id);
      } catch (updateError) {
        console.warn('Could not update conversation message ID:', updateError);
      }
    }
    
    console.log(`✅ Message forwarded to Relay edge ${edgeInfo.id}, conversation message: ${replyMessage && 'id' in replyMessage ? replyMessage.id : 'unknown'}`);
  } catch (error) {
    console.error('Failed to forward message:', error);
    await interaction.editReply('❌ Failed to send message. Please try again later.');
  }
}

