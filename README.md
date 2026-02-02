# Relay Server

The backend API server for [Relay](https://github.com/relay-protocol) - a zero-knowledge, privacy-focused communication platform.

## Overview

Relay Server provides the core backend infrastructure for the Relay protocol, enabling:

- **Zero-Knowledge Architecture**: Server cannot decrypt user data or identify communication partners
- **Identity Management**: Cryptographic identity creation with Ed25519/X25519 keypairs
- **Edge Management**: Disposable contact surfaces (handles, email aliases, bridge endpoints)
- **Double Ratchet Messaging**: Forward-secret E2E encrypted native messaging
- **Email Bridge**: Secure email gateway with transient recipient decryption
- **Bridge Infrastructure**: Foundation for Discord, Telegram, SMS, and other communication bridges

## Security & Privacy

**Relay follows a zero-knowledge design:**

- ✅ Server cannot decrypt message content (Double Ratchet encrypted client-side)
- ✅ Server cannot identify recipients (encrypted for workers, hashed for matching)
- ✅ Server cannot link edges to user identities (architectural separation)
- ✅ Workers decrypt recipients transiently only (never stored)
- ✅ Minimal metadata collection (timestamps rounded to 5 minutes, no IP logging)
- ✅ Cryptographic signatures verify all worker communications

See [RELAY_ETHOS.md](../RELAY_ETHOS.md) for complete security principles and [RELAY_THREAT_MODEL.md](../relay-protocol/RELAY_THREAT_MODEL.md) for threat analysis.

## Architecture

Relay Server is built with a zero-knowledge, defense-in-depth approach:

- **Runtime**: Node.js 18+ with TypeScript
- **Framework**: [Hono](https://hono.dev) - Fast, lightweight web framework
- **Database**: PostgreSQL 14+ with [Drizzle ORM](https://orm.drizzle.team)
- **Crypto**: TweetNaCl (Ed25519, X25519, XSalsa20-Poly1305)
- **Auth**: JWT-based sessions with Ed25519 signature verification
- **Workers**: Cloudflare Workers for bridge transient decryption
- **Email**: Resend API for outbound email delivery

### Zero-Knowledge Components

1. **API Server (Railway)**: Stores encrypted messages, routes data, never decrypts
2. **Email Worker (Cloudflare)**: Decrypts recipient emails transiently for sending
3. **Client (Extension)**: All Double Ratchet encryption/decryption happens here

```
Native Messaging:
Client A → [Double Ratchet Encrypt] → API → [Store Ciphertext] → Client B → [Double Ratchet Decrypt]

Email Bridge:
External Email → Worker → [Encrypt for User] → API → [Store] → Client → [Decrypt]
Client → [Encrypt] → API → Worker → [Decrypt Recipient Only] → Resend → External Email
```

## Prerequisites

- Node.js 18+
- PostgreSQL 14+
- `openssl` (for generating secrets)

## Local Development

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Create a `.env` file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/relay

# Server
PORT=3000
NODE_ENV=development

# Authentication & Security
JWT_SECRET=<generate-with-openssl>

# Worker Authentication
WORKER_SECRET=<generate-with-openssl>  # Shared secret for worker auth
WORKER_PUBLIC_KEY=<ed25519-public-key-hex>  # Worker's Ed25519 public key for signature verification

# Email
RESEND_API_KEY=<your-resend-api-key>  # For sending emails via Resend

# Optional
DATABASE_URL_UNPOOLED=<connection-pooler-url>  # For migrations
```

**Generate secrets:**
```bash
# JWT Secret (32 bytes)
openssl rand -hex 32

# Worker Secret (32 bytes)
openssl rand -hex 32

# Worker Ed25519 keypair (see email-worker/README.md)
```

### 3. Initialize Database

Run migrations to create the schema:

```bash
npm run db:migrate
```

### 4. Start Development Server

```bash
npm run dev
```

The server will start on `http://localhost:3000`.

## API Endpoints

### Authentication
- `POST /v1/auth/register` - Create new identity with public key
- `POST /v1/auth/login` - Authenticate via Ed25519 signature challenge

### Identity
- `GET /v1/identity` - Get current user's identity
- `GET /v1/identity/:id` - Get identity by ID
- `PUT /v1/identity` - Update identity profile

### Edges (Communication Endpoints)
- `POST /v1/edges` - Create new edge (email alias, future: Discord, Telegram, etc.)
- `GET /v1/edges` - List user's edges
- `GET /v1/edges/:id` - Get edge details
- `DELETE /v1/edges/:id` - Delete edge

### Conversations
- `GET /v1/conversations` - List conversations
- `GET /v1/conversations/:id` - Get conversation details
- `GET /v1/conversations/:id/messages` - Get messages (returns encrypted content)
- `POST /v1/conversations/:id/messages` - Send message (accepts encrypted content)

### Email (Bridge)
- `POST /v1/email/inbound` - Receive email from worker (internal, worker-authenticated)
- `POST /v1/email/send` - Prepare email send (returns context for client)
- `POST /v1/email/record-sent` - Record sent message (accepts encrypted content)

### Handles (Native Messaging)
- `POST /v1/handles` - Create handle (&username) with X25519 edge key
- `POST /v1/handles/resolve` - Resolve handle to public key + edge info
- `GET /v1/handles` - List user's handles
- `DELETE /v1/handles/:id` - Delete handle

### Messages (Unified Endpoint)
- `POST /v1/messages` - Send message (supports new conversations via `recipient_handle`)

## Database Schema

The server uses PostgreSQL with the following core tables:

- **identities**: User accounts with Ed25519 public keys
- **handles**: Native handles (&username) linked to identities
- **edges**: Communication endpoints (email aliases, handles, bridge connections)
  - `x25519_public_key`: Per-edge encryption key for Double Ratchet
- **conversations**: Message threads with origin tracking
- **conversation_participants**: Participants with hashed external IDs (zero-knowledge)
- **messages**: Encrypted message content with Double Ratchet metadata
  - `ciphertext`: Encrypted content (base64)
  - `ephemeral_pubkey`: DH public key for ratchet (base64)
  - `nonce`: AEAD nonce (base64)
  - `ratchet_pn`: Previous chain length (Double Ratchet)
  - `ratchet_n`: Message number in chain (Double Ratchet)
- **email_messages**: Email-specific metadata (Message-ID, In-Reply-To)

**Key zero-knowledge features:**
- Message content stored as Double Ratchet ciphertext (forward secrecy)
- Edge-level X25519 keys for per-conversation encryption
- External IDs (email addresses) stored as salted hashes for conversation matching
- Bridge credentials encrypted in `edges.metadata`
- Timestamps rounded to 5 minutes
- No IP address logging

See [`drizzle/`](./drizzle/) for full schema migrations.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Run production server |
| `npm run db:push` | Push schema changes to database |
| `npm run db:studio` | Open Drizzle Studio (DB GUI) |
| `npm run typecheck` | Type-check without building |

## Deployment

### Railway

This server is designed to deploy seamlessly to [Railway](https://railway.app):

1. Push to GitHub
2. Create new Railway project from GitHub repo
3. Add PostgreSQL database addon
4. Set environment variables (see `.env.example`)
5. Railway auto-detects build/start commands
6. Push schema: `railway run npx drizzle-kit push`

### Other Platforms

The server works on any Node.js platform (Render, Fly.io, etc.):

- **Build**: `npm run build`
- **Start**: `npm start`
- Ensure `DATABASE_URL` and other env vars are set

## Security

### Zero-Knowledge Guarantees

- ✅ **Double Ratchet encryption** - Forward secrecy, post-compromise security
- ✅ **Message content encrypted client-side** - Server stores ciphertext only
- ✅ **Edge-level keys** - Per-handle X25519 keypairs for ratchet initialization
- ✅ **Recipient addresses encrypted** - Workers decrypt transiently, never store
- ✅ **External IDs hashed** - Email addresses, Discord IDs stored as salted hashes
- ✅ **Worker authentication** - Ed25519 signatures verify all worker communications
- ✅ **No IP logging** - Rate limiting by identity, not IP address
- ✅ **Minimal metadata** - Timestamps rounded, no behavioral tracking
- ✅ **Architectural isolation** - Edges not directly linked to identities

### Authentication & Authorization

- **User auth**: JWT tokens with Ed25519 signature verification
- **Worker auth**: Shared secret + Ed25519 payload signatures
- **CORS**: Configured for extensions and production domains
- **SQL injection**: Parameterized queries via Drizzle ORM

### Threat Model

See [../relay-protocol/RELAY_THREAT_MODEL.md](../relay-protocol/RELAY_THREAT_MODEL.md) for comprehensive threat analysis.

**Primary defense:** Even if server is fully compromised (database, API, everything), attacker cannot:
- Decrypt message content (no keys on server)
- Identify users (architectural separation)
- Link edges to identities (requires multiple correlations + decryption)
- Read historical messages (encrypted with user keys)

## Related Projects

- **[relay-protocol](../relay-protocol/)**: Protocol specification, threat model, and architecture docs
- **[relay-client](../relay-client/)**: Browser extension and core crypto library
- **[email-worker](./email-worker/)**: Cloudflare Worker for email bridge with transient decryption
- **[RELAY_ETHOS.md](../RELAY_ETHOS.md)**: Security & privacy principles and implementation standards
- **[RELAY_TODO.md](../RELAY_TODO.md)**: Development roadmap and planned features

## License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

For major changes, please open an issue first to discuss.

## Support

For issues, questions, or feature requests:

- Open an issue on [GitHub](https://github.com/yourusername/relay-server/issues)
- See the [Relay Protocol Specification](https://github.com/yourusername/relay-protocol)

---

Built with privacy and user control as core principles.
