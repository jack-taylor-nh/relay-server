/**
 * Relay Discord Worker
 * 
 * Railway-hosted Discord bot that enables bidirectional messaging
 * between Relay users and Discord users via DMs.
 * 
 * Architecture mirrors email-worker:
 * - Inbound: Discord DM → Encrypt with recipient's edge X25519 key → Forward to Relay API
 * - Outbound: Relay API calls /send endpoint → Decrypt recipient → Send Discord DM
 * 
 * Flow (Inbound - Discord user sends DM to bot):
 * 1. Discord user sends DM to bot
 * 2. Bot looks up edge by Discord user ID
 * 3. Bot encrypts message with recipient's edge X25519 public key (zero-knowledge)
 * 4. Bot forwards encrypted content to Relay API
 * 
 * Flow (Outbound - Relay user sends to Discord):
 * 1. Relay API calls bot's HTTP endpoint with encrypted recipient
 * 2. Bot decrypts recipient Discord ID using its X25519 private key
 * 3. Bot sends DM to Discord user
 */

import 'dotenv/config';
import { Client, GatewayIntentBits, Events, Partials, Message, ChatInputCommandInteraction } from 'discord.js';
import { createServer } from 'http';
import { handleInboundDM, handleSlashCommand } from './handlers/inbound.js';
import { createHttpServer } from './http/server.js';
import { getWorkerPublicKey } from './crypto.js';

// Environment validation
const requiredEnvVars = [
  'DISCORD_BOT_TOKEN',
  'DISCORD_APPLICATION_ID',
  'API_BASE_URL',
  'API_SECRET',
  'WORKER_ENCRYPTION_PRIVATE_KEY',
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Discord client setup
const client = new Client({
  intents: [
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.Guilds, // Required for slash commands
  ],
  partials: [
    Partials.Channel, // Required for DM events
    Partials.Message,
  ],
});

// Bot ready event
client.once(Events.ClientReady, (readyClient) => {
  console.log(`✅ Discord bot ready as ${readyClient.user.tag}`);
  console.log(`   Application ID: ${process.env.DISCORD_APPLICATION_ID}`);
  console.log(`   Worker Public Key: ${getWorkerPublicKey().substring(0, 20)}...`);
});

// Handle incoming DMs (legacy text-based fallback)
client.on(Events.MessageCreate, async (message: Message) => {
  // Ignore bot messages
  if (message.author.bot) return;
  
  // Only handle DMs
  if (!message.channel.isDMBased()) return;
  
  console.log(`📥 Received DM from ${message.author.tag} (${message.author.id})`);
  
  try {
    await handleInboundDM(message);
  } catch (error) {
    console.error('Error handling DM:', error);
    // Don't reply with error to avoid leaking info
  }
});

// Handle slash command interactions
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  
  if (interaction.commandName === 'relay') {
    console.log(`📥 Received /relay command from ${interaction.user.tag} (${interaction.user.id})`);
    
    try {
      await handleSlashCommand(interaction as ChatInputCommandInteraction);
    } catch (error) {
      console.error('Error handling slash command:', error);
      
      // Reply with generic error (safe to show since slash commands are explicit)
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({ 
          content: '❌ Sorry, something went wrong. Please try again later.',
          ephemeral: true 
        });
      }
    }
  }
});

// Error handling
client.on(Events.Error, (error) => {
  console.error('Discord client error:', error);
});

// Start Discord bot
console.log('🚀 Starting Relay Discord Worker...');
client.login(process.env.DISCORD_BOT_TOKEN);

// Start HTTP server for outbound messages
const httpServer = createHttpServer(client);
const HTTP_PORT = process.env.PORT || 3001;

httpServer.listen(HTTP_PORT, () => {
  console.log(`🌐 HTTP server listening on port ${HTTP_PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down...');
  client.destroy();
  httpServer.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down...');
  client.destroy();
  httpServer.close();
  process.exit(0);
});
