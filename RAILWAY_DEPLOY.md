# Relay Server - Railway Deployment

## Quick Deploy to Railway

### 1. After pushing to GitHub, deploy to Railway:

1. Go to [Railway](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your `relay-server` repository
4. Railway will auto-detect it as a Node.js project

### 2. Configure Environment Variables

In Railway project settings, add these variables:

```
DATABASE_URL=<already-connected-from-postgres-addon>
JWT_SECRET=<generate-new-secret>
WORKER_SECRET=<generate-new-secret>
EMAIL_DOMAIN=rlymsg.com
PORT=3000
```

**Generate secrets:**
```bash
# JWT Secret
openssl rand -base64 32

# Worker Secret  
openssl rand -base64 32
```

### 3. Build Configuration

Railway should automatically detect:
- **Build Command**: `npm run build`
- **Start Command**: `npm start`

If not, manually set in Railway Settings → Deploy:
- Build Command: `npm run build`
- Start Command: `npm start`

### 4. Database Setup

1. In Railway, add a PostgreSQL database addon to your project
2. Railway will automatically inject `DATABASE_URL`
3. Run migrations by adding a "Deploy Trigger" or manually:
   - Go to your deployment
   - Open the deployment shell
   - Run: `npm run db:migrate`

### 5. Verify Deployment

Once deployed, Railway will provide a public URL like:
`https://relay-server-production-xxxx.up.railway.app`

Test the API:
```bash
curl https://your-railway-url.railway.app/health
```

## Important Notes

- The server is configured to accept CORS from Chrome extensions, localhost, and userelay.org domains
- Database migrations must be run manually after first deployment
- Environment variables are securely stored in Railway
- The PostgreSQL addon provides automatic backups

## Troubleshooting

If build fails:
- Check Railway build logs
- Verify all dependencies are in `package.json` (not just devDependencies)
- Ensure TypeScript compiles without errors locally first

If server won't start:
- Verify `DATABASE_URL` is set correctly
- Check that `PORT` environment variable is respected (Railway sets this automatically)
- Review server logs in Railway dashboard
