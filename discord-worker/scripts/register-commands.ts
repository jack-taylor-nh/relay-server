/**
 * Discord Slash Command Registration
 * 
 * Run this once to register the /relay command with Discord's API.
 * This makes it show up as a real slash command with autocomplete.
 * 
 * Usage: npx tsx scripts/register-commands.ts
 */

import { REST, Routes, SlashCommandBuilder } from 'discord.js';
import * as dotenv from 'dotenv';

dotenv.config();

const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_APPLICATION_ID = process.env.DISCORD_APPLICATION_ID;

if (!DISCORD_BOT_TOKEN || !DISCORD_APPLICATION_ID) {
  console.error('❌ Missing DISCORD_BOT_TOKEN or DISCORD_APPLICATION_ID in .env');
  process.exit(1);
}

// Define slash commands
const commands = [
  new SlashCommandBuilder()
    .setName('relay')
    .setDescription('Send a message to a Relay user')
    .addStringOption(option =>
      option
        .setName('handle')
        .setDescription('The Relay handle to message (e.g., &alice or alice)')
        .setRequired(true)
    )
    .addStringOption(option =>
      option
        .setName('message')
        .setDescription('The message to send')
        .setRequired(true)
    )
    .toJSON(),
];

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN!);

  try {
    console.log('🔄 Registering slash commands...');

    // Register globally (takes up to 1 hour to propagate)
    // For testing, you can register to a specific guild instead (instant)
    await rest.put(
      Routes.applicationCommands(DISCORD_APPLICATION_ID!),
      { body: commands }
    );

    console.log('✅ Slash commands registered successfully!');
    console.log('');
    console.log('Commands registered:');
    console.log('  /relay <handle> <message> - Send a message to a Relay user');
    console.log('');
    console.log('Note: Global commands may take up to 1 hour to appear.');
    console.log('For instant testing, use guild-specific registration.');
  } catch (error) {
    console.error('❌ Failed to register commands:', error);
    process.exit(1);
  }
}

// Also provide a function for guild-specific registration (instant)
async function registerGuildCommands(guildId: string) {
  const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN!);

  try {
    console.log(`🔄 Registering slash commands to guild ${guildId}...`);

    await rest.put(
      Routes.applicationGuildCommands(DISCORD_APPLICATION_ID!, guildId),
      { body: commands }
    );

    console.log('✅ Slash commands registered to guild successfully!');
    console.log('Commands should appear immediately.');
  } catch (error) {
    console.error('❌ Failed to register guild commands:', error);
    process.exit(1);
  }
}

// Check for guild ID argument
const guildId = process.argv[2];
if (guildId) {
  registerGuildCommands(guildId);
} else {
  registerCommands();
}
