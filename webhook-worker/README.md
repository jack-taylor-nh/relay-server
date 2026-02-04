# Relay Webhook Worker

Express server that receives webhooks from external services and forwards them to the Relay API.

## Deployment to Railway

### 1. Prerequisites
- Railway account (https://railway.app)
- GitHub repo with this code (or use Railway CLI)

### 2. Deploy Steps

#### Option A: Deploy from GitHub (Recommended)

1. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Add webhook worker"
   git push
   ```

2. **Create Railway Project:**
   - Go to https://railway.app
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Select your repository
   - Set root directory: `relay-server/webhook-worker`

3. **Configure Environment Variables:**
   In Railway dashboard, go to Variables tab and add:
   ```
   API_BASE_URL=https://your-relay-api.up.railway.app
   API_SECRET=your-worker-auth-secret
   WORKER_ENCRYPTION_PRIVATE_KEY=<generate this>
   WORKER_PRIVATE_KEY=<generate this>
   ```

4. **Generate Encryption Keys:**
   ```bash
   # In relay-server/webhook-worker directory
   npm install
   npm run generate-keys
   ```
   Copy the output keys to Railway environment variables

5. **Deploy:**
   - Railway will auto-detect Node.js and deploy
   - Wait for deployment to complete
   - Copy your Railway URL (e.g., `https://webhook-worker-production.up.railway.app`)

#### Option B: Deploy with Railway CLI

```bash
cd relay-server/webhook-worker
railway login
railway init
railway up
railway variables set API_BASE_URL=https://your-relay-api.up.railway.app
railway variables set API_SECRET=your-worker-auth-secret
# ... set other variables
```

### 3. Verify Deployment

```bash
# Check health
curl https://your-worker.up.railway.app/health

# Get public key
curl https://your-worker.up.railway.app/public-key
```

### 4. Update Extension

Update the webhook URL in your extension:
```typescript
// relay-client/extension/src/background/index.ts
const webhookUrl = `https://your-worker.up.railway.app/w/${edgeId}?auth=${authToken}`;
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 3000, Railway sets automatically) |
| `API_BASE_URL` | Yes | Relay API URL (e.g., `https://api.rlymsg.com`) |
| `API_SECRET` | Yes | Worker authentication secret for API |
| `WORKER_ENCRYPTION_PRIVATE_KEY` | Yes | X25519 private key (hex) for encrypting payloads |
| `WORKER_PRIVATE_KEY` | Yes | Ed25519 private key (hex) for signing requests |

## Local Development

```bash
# Install dependencies
npm install

# Generate encryption keys
npm run generate-keys

# Create .env file
cat > .env << EOF
API_BASE_URL=http://localhost:8787
API_SECRET=dev-secret-123
WORKER_ENCRYPTION_PRIVATE_KEY=<from generate-keys>
WORKER_PRIVATE_KEY=<from generate-keys>
EOF

# Run in development mode
npm run dev

# Test webhook
curl -X POST http://localhost:3000/w/test-edge-id \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "test-service",
    "title": "Test webhook",
    "body": "This is a test message"
  }'
```

## API Endpoints

### `GET /health`
Health check endpoint
- Returns: `{ status: "healthy", timestamp: "...", service: "relay-webhook-worker" }`

### `GET /public-key`
Get worker's X25519 public key
- Returns: `{ publicKey: "base64..." }`

### `POST /w/:edgeId`
Receive webhook for specific edge
- URL Parameters: `edgeId` - Webhook edge ID
- Query Parameters (optional): `auth` - Authentication token
- Headers: `Authorization: Bearer {token}` (alternative to query param)
- Body: JSON webhook payload

## Architecture

```
External Service (GitHub, Stripe, etc.)
          ↓
   Webhook Worker (Railway)
     - Validates auth token
     - Encrypts payload with user's X25519 key
     - Signs request with Ed25519 key
          ↓
   Relay API (Main Server)
     - Stores encrypted message
     - Publishes SSE update
          ↓
   User's Extension
     - Receives SSE notification
     - Decrypts message
     - Displays in inbox
```

## Security

- **Auth tokens**: Each webhook edge has unique token, stored in metadata
- **End-to-end encryption**: Payload encrypted with user's X25519 public key
- **Request signing**: Worker signs requests with Ed25519 for authenticity
- **Sender privacy**: Sender identifiers hashed for conversation matching

## Monitoring

Railway provides:
- Deployment logs
- Application logs
- Metrics dashboard
- Automatic health checks

View logs:
```bash
railway logs
```
