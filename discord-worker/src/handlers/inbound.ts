/**
 * Inbound DM Handler
 * 
 * Processes Discord DMs and forwards them to Relay users using Components V2
 * 
 * Flow:
 * 1. Discord user DMs bot: "/relay @handle message" or uses Reply/New Convo buttons
 * 2. Bot parses command to extract target Relay edge and message
 * 3. Bot looks up target Relay edge by handle
 * 4. Bot encrypts message with target's edge X25519 public key (zero-knowledge)
 * 5. Bot forwards to Relay API for storage
 * 6. Bot creates/updates a Components V2 conversation message with buttons
 * 
 * The Discord user does NOT need a Relay account - they're messaging
 * a Relay user through the bridge.
 */

import { Message, ChatInputCommandInteraction, ModalSubmitInteraction, ButtonInteraction } from 'discord.js';
import { lookupEdgeByHandle, forwardToApi, updateConversationMessageId, lookupExistingConversation } from '../api.js';
import { encryptPayload, hashDiscordId, encryptForWorkerStorage } from '../crypto.js';
import {
  buildConversationComponents,
  buildReplyModal,
  buildNewConversationModal,
  formatDiscordTimestamp,
  MESSAGE_FLAGS,
  CUSTOM_IDS,
  parseCustomId,
  MessageEntry,
  ConversationContext,
  getDiscordAvatarUrl,
  parseExistingMessages,
} from './components.js';

// Command format: /relay &handle message OR /relay handle message
const RELAY_COMMAND_REGEX = /^\/relay\s+[&@]?([a-zA-Z0-9_-]+)\s+(.+)$/s;

// Maximum messages to keep in conversation
const MAX_CONVERSATION_MESSAGES = 10;

// Help message
const HELP_MESSAGE = `**Relay Bot** - Send messages to Relay users

**Usage:**
\`/relay &handle Your message here\`
Or use the **Reply** / **New Conversation** buttons on any conversation.

**Example:**
\`/relay &alice Hey, can we chat?\`

The Relay user will receive your message and can reply back to you here.

Learn more: https://userelay.org`;

/**
 * Send a message via Components V2 REST API
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
 * Parse messages from legacy text format (for backwards compatibility)
 */
function parseExistingMessagesFromLegacy(content: string): MessageEntry[] {
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
 * Fetch existing message components from Discord API
 */
async function fetchMessageComponents(channelId: string, messageId: string): Promise<any[] | null> {
  try {
    const response = await fetch(
      `https://discord.com/api/v10/channels/${channelId}/messages/${messageId}`,
      {
        method: 'GET',
        headers: {
          'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}`,
        },
      }
    );
    
    if (!response.ok) {
      console.warn(`Could not fetch message ${messageId}: ${response.status}`);
      return null;
    }
    
    const data = await response.json() as { components?: any[]; content?: string };
    
    // Return components if present
    if (data.components && data.components.length > 0) {
      return data.components;
    }
    
    return null;
  } catch (error) {
    console.warn('Error fetching message:', error);
    return null;
  }
}

/**
 * Core function to send a message to a Relay user and create/update the conversation UI
 */
async function sendToRelayUser(params: {
  discordUserId: string;
  discordDisplayName: string;
  discordAvatarHash?: string | null;
  targetHandle: string;
  messageContent: string;
  messageId: string;
  channelId: string;
  existingConversationMessageId?: string;
  isSlashCommand?: boolean;
}): Promise<{ success: boolean; conversationMessageId?: string; error?: string }> {
  const { discordUserId, discordDisplayName, discordAvatarHash, targetHandle, messageContent, messageId, channelId, existingConversationMessageId } = params;
  
  // Look up target Relay edge by handle
  const edgeInfo = await lookupEdgeByHandle(targetHandle);
  if (!edgeInfo) {
    return { success: false, error: `Relay user \`&${targetHandle}\` not found.` };
  }
  
  // Hash sender's Discord ID for conversation matching
  const senderHash = await hashDiscordId(discordUserId);
  
  // Check if conversation already exists
  const existingConversation = await lookupExistingConversation(senderHash, edgeInfo.id);
  const conversationMessageId = existingConversationMessageId || existingConversation?.conversationMessageId;
  
  // Encrypt Discord user ID for reply routing
  const encryptedDiscordId = encryptForWorkerStorage(discordUserId);
  
  // Build message payload
  const messagePayload = {
    content: messageContent,
    senderDisplayName: discordDisplayName,
    messageId,
    timestamp: new Date().toISOString(),
  };
  
  // Build counterparty metadata
  const counterpartyMetadata = {
    counterpartyDisplayName: discordDisplayName,
    platform: 'discord',
  };
  
  // Encrypt payloads
  const encryptedPayload = encryptPayload(messagePayload, edgeInfo.x25519PublicKey);
  const encryptedMetadata = encryptPayload(counterpartyMetadata, edgeInfo.x25519PublicKey);
  
  const timestamp = formatDiscordTimestamp();
  
  // Forward to Relay API
  const apiResult = await forwardToApi({
    edgeId: edgeInfo.id,
    senderHash,
    encryptedRecipientId: encryptedDiscordId,
    encryptedPayload,
    encryptedMetadata,
    discordMessageId: messageId,
    receivedAt: new Date().toISOString(),
  });
  
  const conversationId = apiResult?.conversationId || existingConversation?.conversationId;
  
  // New message from Discord user
  const newMessage: MessageEntry = {
    from: 'discord',
    senderName: 'You',
    content: messageContent,
    timestamp,
    avatarUrl: getDiscordAvatarUrl(discordUserId, discordAvatarHash),
  };
  
  // Build conversation context - fetch existing messages if we have a conversation message
  let existingMessages: MessageEntry[] = [];
  
  if (conversationMessageId) {
    // Fetch existing components from Discord
    const existingComponents = await fetchMessageComponents(channelId, conversationMessageId);
    if (existingComponents) {
      existingMessages = parseExistingMessages(existingComponents);
      console.log(`📜 Parsed ${existingMessages.length} existing messages from conversation`);
    }
  }
  
  // Add new message
  existingMessages.push(newMessage);
  
  // Truncate if needed
  if (existingMessages.length > MAX_CONVERSATION_MESSAGES) {
    existingMessages = existingMessages.slice(-MAX_CONVERSATION_MESSAGES);
  }
  
  const context: ConversationContext = {
    targetHandle,
    messages: existingMessages,
    securityLevel: 'relayed',
    discordUserId,
    discordAvatarHash: discordAvatarHash || undefined,
  };
  
  let newConversationMessageId: string;
  
  if (conversationMessageId) {
    // Try to edit existing message
    try {
      await editMessageWithComponentsV2(
        channelId,
        conversationMessageId,
        buildConversationComponents(context)
      );
      newConversationMessageId = conversationMessageId;
    } catch (editError) {
      console.warn('Could not edit existing conversation, creating new:', editError);
      // Fall through to create new
      newConversationMessageId = await sendMessageWithComponentsV2(
        channelId,
        buildConversationComponents(context)
      );
    }
  } else {
    // Create new Components V2 conversation message
    newConversationMessageId = await sendMessageWithComponentsV2(
      channelId,
      buildConversationComponents(context)
    );
  }
  
  // Store the conversation message ID
  if (newConversationMessageId && conversationId) {
    try {
      await updateConversationMessageId(conversationId, newConversationMessageId);
    } catch (updateError) {
      console.warn('Could not update conversation message ID:', updateError);
    }
  }
  
  return { success: true, conversationMessageId: newConversationMessageId };
}

/**
 * Handle an inbound Discord DM (legacy text command)
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
        content: `👋 Hi! To message a Relay user, use:\n\`/relay &handle Your message\`\n\nOr use the buttons on any conversation. Type \`help\` for more info.`,
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
  
  try {
    const result = await sendToRelayUser({
      discordUserId,
      discordDisplayName: message.author.displayName,
      discordAvatarHash: message.author.avatar,
      targetHandle,
      messageContent,
      messageId: message.id,
      channelId: message.channel.id,
    });
    
    if (result.success) {
      await message.react('✅');
      console.log(`✅ Created/updated conversation for ${targetHandle}`);
    } else {
      await message.reply(`❌ ${result.error}`);
    }
  } catch (error) {
    console.error('Failed to forward message:', error);
    await message.reply('❌ Failed to send message. Please try again later.');
  }
}

/**
 * Handle the /relay slash command
 * This is the preferred method as it shows up as a real Discord command
 * 
 * If run in a public channel, we redirect the conversation to DMs.
 * If a conversation already exists with this Relay handle, we edit the existing
 * conversation message. Otherwise, we create a new one.
 */
export async function handleSlashCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  const discordUserId = interaction.user.id;
  const discordUsername = interaction.user.tag;
  const discordDisplayName = interaction.user.displayName;
  
  // Check if this is in a DM or public channel
  const isInDM = !interaction.guild;
  
  // Get command options
  const handleInput = interaction.options.getString('handle', true);
  const messageContent = interaction.options.getString('message', true);
  
  // Clean the handle (remove & or @ if present)
  const targetHandle = handleInput.replace(/^[&@]/, '').toLowerCase();
  
  console.log(`📥 /relay from ${discordUsername} → &${targetHandle}: "${messageContent.substring(0, 50)}..." (${isInDM ? 'DM' : 'public channel'})`);
  
  // Defer reply - ephemeral if in public channel (only visible to user)
  await interaction.deferReply({ ephemeral: !isInDM });
  
  try {
    // Get or create DM channel for the user
    const user = await interaction.client.users.fetch(discordUserId);
    const dmChannel = await user.createDM();
    
    const result = await sendToRelayUser({
      discordUserId,
      discordDisplayName,
      discordAvatarHash: interaction.user.avatar,
      targetHandle,
      messageContent,
      messageId: interaction.id,
      channelId: dmChannel.id,
      isSlashCommand: true,
    });
    
    if (result.success) {
      if (isInDM) {
        // Delete the deferred reply since we created a conversation message
        await interaction.deleteReply();
      } else {
        // In public channel - tell user to check DMs
        await interaction.editReply(`✅ Message sent to **&${targetHandle}**. Check your DMs for the conversation.`);
      }
      console.log(`✅ Created/updated conversation for ${targetHandle}`);
    } else {
      await interaction.editReply(`❌ ${result.error}`);
    }
  } catch (error) {
    console.error('Failed to forward message:', error);
    await interaction.editReply('❌ Failed to send message. Please try again later.');
  }
}

/**
 * Handle Reply button click
 * Opens a modal for the user to enter their reply
 */
export async function handleReplyButton(interaction: ButtonInteraction): Promise<void> {
  const { handle } = parseCustomId(interaction.customId);
  
  if (!handle) {
    await interaction.reply({
      content: '❌ Could not determine conversation. Please use `/relay &handle message` instead.',
      ephemeral: true,
    });
    return;
  }
  
  console.log(`📥 Reply button clicked for &${handle} by ${interaction.user.tag}`);
  
  // Show the reply modal
  await interaction.showModal(buildReplyModal(handle));
}

/**
 * Handle New Conversation button click
 * Opens a modal for the user to enter a new handle and message
 */
export async function handleNewConversationButton(interaction: ButtonInteraction): Promise<void> {
  console.log(`📥 New Conversation button clicked by ${interaction.user.tag}`);
  
  // Show the new conversation modal
  await interaction.showModal(buildNewConversationModal());
}

/**
 * Handle Reply modal submission
 */
export async function handleReplyModalSubmit(interaction: ModalSubmitInteraction): Promise<void> {
  const { handle } = parseCustomId(interaction.customId);
  
  if (!handle) {
    await interaction.reply({
      content: '❌ Could not determine conversation. Please use `/relay &handle message` instead.',
      ephemeral: true,
    });
    return;
  }
  
  const messageContent = interaction.fields.getTextInputValue(CUSTOM_IDS.REPLY_MESSAGE_INPUT);
  
  if (!messageContent.trim()) {
    await interaction.reply({
      content: '❌ Please enter a message.',
      ephemeral: true,
    });
    return;
  }
  
  console.log(`📥 Reply modal submitted for &${handle} by ${interaction.user.tag}: "${messageContent.substring(0, 50)}..."`);
  
  // Defer the reply
  await interaction.deferReply({ ephemeral: true });
  
  try {
    const result = await sendToRelayUser({
      discordUserId: interaction.user.id,
      discordDisplayName: interaction.user.displayName,
      discordAvatarHash: interaction.user.avatar,
      targetHandle: handle,
      messageContent: messageContent.trim(),
      messageId: interaction.id,
      channelId: interaction.channelId || '',
      existingConversationMessageId: interaction.message?.id,
    });
    
    if (result.success) {
      // Delete the ephemeral reply since conversation was updated
      await interaction.deleteReply();
      console.log(`✅ Reply sent to &${handle}`);
    } else {
      await interaction.editReply(`❌ ${result.error}`);
    }
  } catch (error) {
    console.error('Failed to send reply:', error);
    await interaction.editReply('❌ Failed to send reply. Please try again later.');
  }
}

/**
 * Handle New Conversation modal submission
 */
export async function handleNewConversationModalSubmit(interaction: ModalSubmitInteraction): Promise<void> {
  const handleInput = interaction.fields.getTextInputValue(CUSTOM_IDS.NEW_HANDLE_INPUT);
  const messageContent = interaction.fields.getTextInputValue(CUSTOM_IDS.NEW_MESSAGE_INPUT);
  
  // Clean the handle
  const targetHandle = handleInput.replace(/^[&@]/, '').toLowerCase().trim();
  
  if (!targetHandle) {
    await interaction.reply({
      content: '❌ Please enter a Relay handle.',
      ephemeral: true,
    });
    return;
  }
  
  if (!messageContent.trim()) {
    await interaction.reply({
      content: '❌ Please enter a message.',
      ephemeral: true,
    });
    return;
  }
  
  console.log(`📥 New conversation modal submitted for &${targetHandle} by ${interaction.user.tag}: "${messageContent.substring(0, 50)}..."`);
  
  // Defer the reply
  await interaction.deferReply({ ephemeral: true });
  
  try {
    // Get DM channel
    const user = await interaction.client.users.fetch(interaction.user.id);
    const dmChannel = await user.createDM();
    
    const result = await sendToRelayUser({
      discordUserId: interaction.user.id,
      discordDisplayName: interaction.user.displayName,
      discordAvatarHash: interaction.user.avatar,
      targetHandle,
      messageContent: messageContent.trim(),
      messageId: interaction.id,
      channelId: dmChannel.id,
    });
    
    if (result.success) {
      // Delete the ephemeral reply since conversation was created
      await interaction.deleteReply();
      console.log(`✅ New conversation started with &${targetHandle}`);
    } else {
      await interaction.editReply(`❌ ${result.error}`);
    }
  } catch (error) {
    console.error('Failed to start conversation:', error);
    await interaction.editReply('❌ Failed to start conversation. Please try again later.');
  }
}


