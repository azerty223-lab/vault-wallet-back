# Railway Deployment Guide

## Quick Start

### 1. Railway Setup
- **Root Directory:** `backend`
- **Start Command:** `npm start`

### 2. Environment Variables
Add these in Railway dashboard under "Variables":

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_URI` | Yes | MongoDB Atlas or Railway MongoDB connection string |
| `SESSION_SECRET` | Yes | Random string for session encryption |
| `FRONTEND_URL` | Yes | Your frontend domain (comma-separated for multiple) |
| `TELEGRAM_BOT_TOKEN` | No | Bot token for wallet notifications |
| `TELEGRAM_CHAT_ID` | No | Chat ID to receive notifications |
| `NODE_ENV` | No | Set to `production` |
| `IPINFO_TOKEN` | No | For IP geolocation |

### 3. MongoDB Setup
**Option A - MongoDB Atlas (Recommended):**
1. Create cluster at https://cloud.mongodb.com
2. Get connection string from "Connect" button
3. Replace `<password>` with your database user password
4. Add to Railway Variables as `MONGO_URI`

**Option B - Railway MongoDB:**
1. Add MongoDB service from Railway marketplace
2. Copy connection string from service details
3. Add to Railway Variables as `MONGO_URI`

### 4. Local Testing
```bash
cd backend
cp .env.example .env
# Edit .env with your values
npm start
```

### 5. Troubleshooting
- **Port already in use:** Stop other processes on port 5001
- **MongoDB connection error:** Check MONGO_URI format and credentials
- **Telegram bot not initializing:** Variables are optional - app works without them
- **CORS errors:** Add your frontend URL to FRONTEND_URL variable

### 6. Deployment Checklist
- [ ] Root directory set to `backend`
- [ ] Start command: `npm start`
- [ ] MONGO_URI added
- [ ] SESSION_SECRET added
- [ ] FRONTEND_URL added with your domain
- [ ] NODE_ENV set to `production`
- [ ] TELEGRAM variables added (optional)
