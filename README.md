# Relay Server

The backend API server for [Relay](https://github.com/yourusername/relay) - a privacy-focused, handle-based communication platform.

## Overview

Relay Server provides the core backend infrastructure for the Relay protocol, enabling:

- **Identity Management**: Cryptographic identity creation and authentication
- **Handle System**: User-friendly handles (e.g., `&alice`) mapped to cryptographic identities
- **Edge Management**: Disposable contact surfaces (email aliases, contact links)
- **E2E Encrypted Messaging**: Native Relay-to-Relay encrypted communication
- **Email Gateway**: Secure email alias forwarding and replies

## Architecture

Relay Server is built with:

- **Runtime**: Node.js with TypeScript
- **Framework**: [Hono](https://hono.dev) - Fast, lightweight web framework
- **Database**: PostgreSQL with [Drizzle ORM](https://orm.drizzle.team)
- **Crypto**: libsodium (Ed25519 + X25519 + XChaCha20-Poly1305)
- **Auth**: JWT-based session tokens with signed challenge-response

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
DATABASE_URL=postgresql://user:password@localhost:5432/relay
PORT=3000
JWT_SECRET=<generate-with-openssl>
WORKER_SECRET=<generate-with-openssl>
EMAIL_DOMAIN=yourdomain.com
```

**Generate secrets:**
```bash
# JWT Secret
openssl rand -base64 32

# Worker Secret
openssl rand -base64 32
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

- `POST /api/auth/nonce` - Request authentication challenge
- `POST /api/auth/verify` - Verify signed challenge and get session token

### Identity

- `GET /api/identity/:id` - Get identity profile
- `PUT /api/identity` - Update identity profile

### Handles

- `POST /api/handles/claim` - Claim a handle
- `GET /api/handles/:name` - Resolve handle to identity
- `GET /api/handles` - List user's handles

### Edges (Contact Surfaces)

- `POST /api/edges` - Create new edge (email alias, contact link)
- `GET /api/edges` - List user's edges
- `PUT /api/edges/:id` - Update edge
- `DELETE /api/edges/:id` - Disable/rotate edge

### Conversations

- `GET /api/conversations` - List conversations
- `GET /api/conversations/:id` - Get conversation details
- `GET /api/conversations/:id/messages` - Get messages

### Email

- `POST /api/email/send` - Send email from alias
- `POST /api/email/webhook` - Receive incoming email (internal)

## Database Schema

The server uses a PostgreSQL database with the following core tables:

- **identities**: Cryptographic identities (public keys)
- **handles**: User-friendly names mapped to identities
- **edges**: Contact surfaces (email aliases, links, bridges)
- **conversations**: Message threads
- **messages**: Individual messages
- **nonces**: Authentication challenges

See [`drizzle/`](./drizzle/) for full schema migrations.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Run production server |
| `npm run db:migrate` | Run database migrations |
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
6. Run migrations: `railway run npm run db:migrate`

### Other Platforms

The server works on any Node.js platform (Render, Fly.io, etc.):

- **Build**: `npm run build`
- **Start**: `npm start`
- Ensure `DATABASE_URL` and other env vars are set

## Security

- All authentication uses Ed25519 signature verification
- Session tokens are JWT-signed with HS256
- Email worker auth uses shared secret (`WORKER_SECRET`)
- CORS configured for Chrome extensions, localhost, and production domains
- Database uses parameterized queries (SQL injection protection)

## Related Projects

- **[relay-protocol](https://github.com/yourusername/relay-protocol)**: Protocol specification and threat model
- **[relay-client](https://github.com/yourusername/relay-client)**: Browser extension and core library

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
