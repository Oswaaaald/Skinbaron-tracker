# 🎯 SkinBaron Tracker

> **Production-grade CS2 skin price monitoring platform** with real-time Discord alerts, advanced filtering, and enterprise-level security.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16.1-black.svg)](https://nextjs.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5.7-green.svg)](https://fastify.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![Project Banner](https://via.placeholder.com/1200x300/1e293b/06b6d4?text=SkinBaron+Tracker)

## 📋 Overview

A full-stack TypeScript application for tracking CS2 (Counter-Strike 2) skin prices on SkinBaron marketplace with customizable alerts sent via Discord webhooks.

**Key Features:**
- 🔔 Real-time price monitoring with cron-based scheduler
- 🎯 Advanced filtering (price, wear, StatTrak, Souvenir, stickers)
- 🔐 Enterprise-grade security (JWT rotation, 2FA, CSRF, AES-256-GCM encryption)
- 👥 Multi-user support with RBAC (admin/super admin)
- 📊 Admin dashboard with audit logs and system metrics
- 🐳 Production-ready Docker deployment
- ⚡ Optimized performance (LRU cache, batch operations, database indexes)

## 🏗️ Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Next.js 16    │◄────►│  Fastify API     │◄────►│  SQLite (WAL)   │
│   (Frontend)    │      │  (Backend)       │      │  (Database)     │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                                 │
                                 ▼
                         ┌──────────────────┐
                         │  SkinBaron API   │
                         │  Scheduler       │
                         └──────────────────┘
                                 │
                                 ▼
                         ┌──────────────────┐
                         │ Discord Webhooks │
                         └──────────────────┘
```

### Tech Stack

**Frontend:**
- Next.js 16 (App Router, React Server Components)
- TypeScript 5.3 (strict mode)
- React Query (TanStack Query)
- Tailwind CSS 4 + shadcn/ui
- Zod validation

**Backend:**
- Fastify 5.7 (Node.js framework)
- TypeScript 5.3 (strict mode)
- SQLite with WAL mode (better-sqlite3)
- JWT authentication with rotation
- CSRF protection (double-submit cookie)
- AES-256-GCM encryption for sensitive data
- TOTP 2FA (otplib)

**Infrastructure:**
- Docker multi-stage builds
- Docker Compose orchestration
- Hardened containers (read-only, non-root, no-new-privileges)
- Cloudflare-ready (CF-Connecting-IP support)
- Health checks & graceful shutdown

## 🚀 Quick Start

### Prerequisites

- Node.js 22+
- npm 11+
- Docker & Docker Compose (optional)

### Local Development

```bash
# Clone repository
git clone https://github.com/Oswaaaald/Skinbaron-tracker.git
cd skinbaron-alerts-sbapi

# Setup environment variables
cp .env.example .env
# Edit .env with your values (see Configuration section)

# Install dependencies
cd backend && npm install
cd ../frontend && npm install

# Run backend (http://localhost:8080)
cd backend && npm run dev

# Run frontend (http://localhost:3000)
cd frontend && npm run dev
```

### Docker Deployment

```bash
# Configure environment
cp .env.example .env
# Edit .env with production values

# Build and start services
docker compose up -d

# Check health
curl http://localhost:8080/api/health
```

## ⚙️ Configuration

### Required Environment Variables

```env
# Security (CRITICAL - Generate strong random values)
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
ENCRYPTION_KEY=different-from-jwt-secret-32-chars

# Network
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
CORS_ORIGIN=https://yourdomain.com
COOKIE_DOMAIN=.yourdomain.com

# Optional
SB_API_KEY=your-skinbaron-api-key (optional)
POLL_CRON=*/5 * * * * (default: every 5 minutes)
RATE_LIMIT_MAX=10000 (default: 10k req/min)
```

**Generate secure secrets:**
```bash
# JWT_SECRET
openssl rand -base64 48

# ENCRYPTION_KEY
openssl rand -base64 48
```

### First User Setup

The first registered user automatically becomes **super admin**.

## 🔐 Security Features

- ✅ **Authentication:** JWT with access/refresh token rotation
- ✅ **Authorization:** Role-based access control (RBAC)
- ✅ **CSRF Protection:** Double-submit cookie pattern
- ✅ **2FA:** TOTP with recovery codes
- ✅ **Encryption:** AES-256-GCM for sensitive data (webhooks, 2FA secrets)
- ✅ **Rate Limiting:** Configurable per-IP + per-user
- ✅ **Helmet:** Security headers (CSP, HSTS, etc.)
- ✅ **Audit Logs:** GDPR-compliant with configurable retention
- ✅ **SQL Injection:** Parameterized queries + foreign key constraints
- ✅ **XSS Protection:** Input validation (Zod) + output encoding

## 📊 Features

### User Features
- Create unlimited price tracking rules (up to 50 per user)
- Configure multiple Discord webhooks
- Advanced filtering (price range, wear value, StatTrak, Souvenir, stickers)
- View alert history with pagination
- 2FA setup with QR code
- Profile management

### Admin Features
- User approval system
- Grant/revoke admin privileges
- View global statistics
- Audit log viewer
- System health monitoring
- Force scheduler run

### System Features
- Automatic price polling (configurable cron)
- Batch processing (10 rules in parallel)
- Discord rate limiting (30 msg/min compliance)
- Graceful shutdown (SIGTERM/SIGINT)
- Health checks (Docker-ready)

## 🎨 Screenshots

> **Dashboard** | **Create Rule** | **2FA Setup** | **Admin Panel**
![Dashboard](https://via.placeholder.com/800x400?text=Dashboard) ![Create Rule](https://via.placeholder.com/800x400?text=Create+Rule) ![2FA Setup](https://via.placeholder.com/800x400?text=2FA+Setup) ![Admin Panel](https://via.placeholder.com/800x400?text=Admin+Panel)

## 📦 Project Structure

```
skinbaron-alerts-sbapi/
├── backend/
│   ├── src/
│   │   ├── database/         # Database layer (repositories, schemas)
│   │   ├── lib/              # Core services (auth, config, middleware)
│   │   ├── routes/           # API endpoints
│   │   └── types/            # TypeScript definitions
│   ├── Dockerfile            # Multi-stage production build
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── app/              # Next.js app router pages
│   │   ├── components/       # React components
│   │   ├── contexts/         # React contexts (auth)
│   │   ├── hooks/            # Custom React hooks
│   │   └── lib/              # Utilities (api client, validation)
│   ├── Dockerfile
│   └── package.json
└── docker-compose.yml        # Orchestration
```

## 🧪 API Documentation

Once running, access interactive API docs:
- **Swagger UI:** `http://localhost:8080/docs`
- **Authentication required:** Login first, then access /docs

### Example API Calls

```bash
# Register new user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john","email":"john@example.com","password":"SecurePass123"}'

# Get CSRF token
curl http://localhost:8080/api/csrf-token --cookie-jar cookies.txt

# Create price rule (authenticated)
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: YOUR_TOKEN" \
  --cookie cookies.txt \
  -d '{"search_item":"AK-47 | Redline","max_price":50,"webhook_ids":[1]}'
```

## 🐳 Docker Details

### Multi-stage Build

```dockerfile
# Backend: 3 stages (deps, builder, runner)
- Stage 1: Install production deps only
- Stage 2: Build TypeScript → JavaScript
- Stage 3: Minimal runtime (Node 22 Alpine + built files)

# Frontend: 3 stages (deps, builder, runner)
- Stage 1: Install all deps
- Stage 2: Next.js standalone build
- Stage 3: Minimal runtime with standalone output
```

### Security Hardening

```yaml
# Applied to both containers
read_only: true              # Filesystem read-only
tmpfs: /tmp                  # Writable /tmp in memory
user: non-root (1001)        # No root privileges
cap_drop: ALL                # Drop all Linux capabilities
no-new-privileges: true      # Prevent privilege escalation
healthcheck: 30s interval    # Auto-restart if unhealthy
```

## 🔧 Development

### Backend Commands

```bash
npm run dev          # Dev server with hot reload (tsx)
npm run build        # TypeScript → JavaScript (dist/)
npm start            # Production server
npm run lint         # ESLint check
npm run type-check   # TypeScript check without emit
```

### Frontend Commands

```bash
npm run dev          # Next.js dev server
npm run build        # Production build (standalone)
npm start            # Serve production build
npm run lint         # ESLint + Next.js lint
```

## 📈 Performance

- **LRU Cache:** 500 users cached (30s TTL)
- **Database Indexes:** 18 indexes covering all queries
- **Batch Operations:** Alert creation in transactions
- **WAL Mode:** SQLite concurrent reads
- **Next.js:** Automatic code splitting + tree shaking
- **React Query:** Request deduplication + background refetch

## 🛠️ Troubleshooting

### "Authentication required to view API documentation"
→ Login first at `/login`, then access `/docs`

### "CSRF token missing"
→ Frontend auto-fetches token on init. Check browser console for errors.

### "Your account is awaiting admin approval"
→ First user is auto-approved. Others need admin approval via admin panel.

### Docker volume permission issues
→ Ensure `skinbaron_backend_data` volume exists:
```bash
docker volume create skinbaron_backend_data
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

**TL;DR:** You can use this code for personal or commercial projects, just keep the copyright notice.

## 🙏 Acknowledgments

- [SkinBaron](https://skinbaron.de) - CS2 marketplace API
- [Fastify](https://fastify.io) - Lightning-fast web framework
- [Next.js](https://nextjs.org) - React framework
- [shadcn/ui](https://ui.shadcn.com) - Beautiful component library

## 👤 Author

**Oswaaaald** - [42 School Transcender](https://42.fr/)

- GitHub: [@Oswaaaald](https://github.com/Oswaaaald)
- Portfolio: [oswaaaald.be](https://oswaaaald.be)

## 🚧 Roadmap

- [ ] Unit tests (Vitest + React Testing Library)
- [ ] E2E tests (Playwright)
- [ ] Prometheus metrics export
- [ ] Multiple marketplace support (CSGOFloat, Buff163)

---

**⭐ Star this repo if you find it useful!**
