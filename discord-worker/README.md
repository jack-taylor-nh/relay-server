# Relay Discord Worker

Railway-hosted Discord bot for bidirectional messaging between Relay users and Discord users.

## Architecture

```
Discord User ←→ Discord Bot ←→ Relay API ←→ Relay Client
```

### Inbound Flow (Discord → Relay)
1. Discord user sends DM to bot
2. Bot looks up edge by Discord user ID
3. Bot encrypts message with recipient's edge X25519 public key (zero-knowledge)
4. Bot forwards encrypted content to Relay API

### Outbound Flow (Relay → Discord)
1. Relay API calls bot's `/send` endpoint with encrypted recipient
2. Bot decrypts recipient Discord ID using its X25519 private key
3. Bot sends DM to Discord user

## Setup

### 1. Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" → Name it "Relay"
3. Go to "Bot" section → Click "Add Bot"
4. Under "Privileged Gateway Intents", enable:
   - **Message Content Intent** (required to read DM content)
5. Copy the **Bot Token** (keep secret!)
6. Go to "OAuth2" → "URL Generator"
   - Select scope: `bot`
   - Select permissions: `Send Messages`, `Read Message History`
   - Copy the generated URL and use it to invite the bot to a test server

### 2. Generate Worker Keypair

```bash
cd discord-worker
npm install
npm run generate-keypair
```

This outputs:
- `WORKER_ENCRYPTION_PRIVATE_KEY` - Add to `.env`
- X25519 public key - Use to register bridge

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```
DISCORD_BOT_TOKEN=your_bot_token_from_step_1
DISCORD_APPLICATION_ID=your_application_id
API_BASE_URL=https://api.rlymsg.com
API_SECRET=your_worker_api_secret
WORKER_ENCRYPTION_PRIVATE_KEY=from_step_2
WORKER_SIGNING_PRIVATE_KEY=from_step_2
```

### 4. Register Discord Bridge

From relay-server root:
```bash
npx tsx scripts/register-discord-bridge.ts <public-key-from-step-2>
```

### 5. Run Locally

```bash
npm run dev
```

### 6. Deploy to Railway

1. Create new project in Railway
2. Connect GitHub repo (or use `railway up`)
3. Set environment variables in Railway dashboard
4. Railway auto-detects Node.js and runs `npm start`

## API Endpoints

### GET /health
Health check endpoint.

```json
{
  "status": "ok",
  "botUser": "Relay#1234",
  "uptime": 3600
}
```

### GET /public-key
Get worker's X25519 encryption public key.

```json
{
  "publicKey": "base64-encoded-public-key"
}
```

### POST /send
Send a Discord DM. Requires `Authorization: Worker <secret>` header.

**Request:**
```json
{
  "conversationId": "conv_123",
  "content": "Hello from Relay!",
  "encryptedRecipient": "ephemeralPubkey:nonce:ciphertext",
  "edgeAddress": "discord:123456789"
}
```

**Response:**
```json
{
  "success": true,
  "messageId": "discord_message_id"
}
```

## Security Model

- **Gateway Secured**: Discord bridge can see plaintext content (required to send/receive Discord messages)
- **Zero-Knowledge Recipients**: Recipient Discord IDs are encrypted for the worker's X25519 key - Relay API never sees them
- **Signed Payloads**: Inbound messages are signed with Ed25519 to prevent injection attacks
