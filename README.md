# 🎯 SkinBaron Tracker

> **Production-grade CS2 skin price monitoring platform** with real-time Discord alerts, advanced filtering, and enterprise-level security.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16.1-black.svg)](https://nextjs.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5.7-green.svg)](https://fastify.io/)
[![React](https://img.shields.io/badge/React-19.2-blue.svg)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![Project Banner](https://oswaaaald.be/images/skinbaron-tracker.png)

## 📋 Overview

A full-stack TypeScript application for tracking CS2 (Counter-Strike 2) skin prices on SkinBaron marketplace with customizable alerts sent via Discord webhooks.

**Key Features:**
- 🔔 Real-time price monitoring with cron-based scheduler
- 🎯 Advanced filtering (price, wear, StatTrak, Souvenir, stickers)
- 🔐 Enterprise-grade security (JWT rotation, 2FA, WebAuthn/Passkeys, CSRF, AES-256-GCM)
- 🔑 OAuth2 login (Google, Discord, GitHub) with account linking
- 👥 Multi-user support with three-tier RBAC (user → admin → super admin)
- 📊 Admin dashboard with audit logs, admin action logs, and system metrics
- 🛡️ Account restriction system (temporary + permanent sanctions)
- 📸 Avatar upload with Gravatar fallback
- 📦 GDPR-compliant (data export, account self-deletion, audit log retention, cookie consent)
- 🐳 Production-ready Docker deployment with security hardening
- ⚡ Optimized performance (LRU cache, batch operations, database indexes)

## 🏗️ Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Next.js 16    │◄────►│  Fastify API     │◄────►│  PostgreSQL 17  │
│   (Frontend)    │      │  (Backend)       │      │  (Drizzle ORM)  │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                                 │
                         ┌───────┴────────┐
                         ▼                ▼
                  ┌──────────────┐  ┌───────────────┐
                  │ SkinBaron    │  │ OAuth2        │
                  │ API + Cron   │  │ Google/Discord│
                  └──────────────┘  │ GitHub        │
                         │          └───────────────┘
                         ▼
                  ┌──────────────┐
                  │ Discord      │
                  │ Webhooks     │
                  └──────────────┘
```

### Tech Stack

**Frontend:**
- Next.js 16.1 (App Router)
- React 19.2 with TypeScript 5.9 (strict mode)
- TanStack Query (React Query) for data fetching
- Tailwind CSS 4 + shadcn/ui components
- Zod validation (client-side + shared schemas)

**Backend:**
- Fastify 5.7 with TypeScript 5.9 (strict mode)
- PostgreSQL 17 with Drizzle ORM 0.45
- JWT authentication with separate access/refresh signing keys
- CSRF protection (double-submit cookie pattern)
- AES-256-GCM encryption for sensitive data
- TOTP 2FA (otplib) + WebAuthn/Passkeys (FIDO2)
- OAuth2 (Google PKCE, Discord PKCE, GitHub)
- bcrypt (12 rounds) + zxcvbn password strength validation
- Webhook SSRF protection (domain whitelist, DNS check, private IP blocking)

**Infrastructure:**
- Docker multi-stage builds (3 stages each)
- Docker Compose orchestration
- Hardened containers (read-only, non-root, cap_drop ALL, no-new-privileges)
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
# Security (CRITICAL - Generate unique strong random values)
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
JWT_ACCESS_SECRET=separate-access-token-signing-key    # recommended, falls back to JWT_SECRET
JWT_REFRESH_SECRET=separate-refresh-token-signing-key  # recommended, falls back to JWT_SECRET
ENCRYPTION_KEY=different-from-jwt-secrets-32-chars     # MUST differ from JWT secrets

# Network
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
CORS_ORIGIN=https://yourdomain.com
COOKIE_DOMAIN=.yourdomain.com

# Database
POSTGRES_USER=skinbaron
POSTGRES_PASSWORD=your-strong-db-password

# Optional: SkinBaron API
SB_API_KEY=your-skinbaron-api-key

# Optional: OAuth2 providers (leave empty to disable)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=

# Optional: Tuning (defaults shown)
POLL_CRON=*/5 * * * *           # Price check frequency
RATE_LIMIT_MAX=1000             # Requests per window
RATE_LIMIT_WINDOW=60000         # Window duration (ms)
AUDIT_LOG_RETENTION_DAYS=365    # GDPR retention period
ALERT_RETENTION_DAYS=90         # Alert history retention
LOG_LEVEL=info
```

**Generate secure secrets:**
```bash
openssl rand -base64 48  # Run once per secret
```

### First User Setup

The first registered user automatically becomes **super admin** with full platform control.

## 🔐 Security Features

### Authentication
- ✅ **JWT rotation** with separate access/refresh signing keys and token blacklisting
- ✅ **TOTP 2FA** with encrypted secrets and 10 recovery codes
- ✅ **WebAuthn/Passkeys** (FIDO2) — hardware keys, iCloud Keychain, Windows Hello, etc.
- ✅ **OAuth2** — Google (PKCE), Discord (PKCE), GitHub with account linking/unlinking
- ✅ **Password security** — bcrypt (12 rounds), zxcvbn strength validation (score ≥ 3)
- ✅ **Timing-attack prevention** — fake bcrypt hash on non-existent users

### Data Protection
- ✅ **AES-256-GCM encryption** for webhooks, TOTP secrets, recovery codes
- ✅ **CSRF protection** (double-submit cookie with constant-time comparison)
- ✅ **SSRF protection** on webhooks (domain whitelist, DNS check, private IP blocking)
- ✅ **Avatar security** — magic-byte validation, sharp re-encoding, EXIF stripping, random filenames

### Infrastructure
- ✅ **Rate limiting** — global per-IP + strict per-route (5 req/min for auth)
- ✅ **Helmet headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- ✅ **Docker hardening** — read-only FS, non-root, cap_drop ALL, no-new-privileges
- ✅ **SQL injection prevention** — Drizzle ORM parameterized queries + FK constraints
- ✅ **XSS protection** — Zod input validation + React output encoding

### Compliance
- ✅ **GDPR data export** (Art. 20 portability)
- ✅ **Account self-deletion** with identity verification
- ✅ **Audit logs** with configurable retention and auto-cleanup
- ✅ **Cookie consent** banner

> See [SECURITY.md](SECURITY.md) for full security architecture details.

## 📊 Features

### User Features
- Create price tracking rules (up to 50 per user) with advanced filtering
- Configure multiple Discord webhooks (up to 20, compact or detailed notification style)
- Advanced filtering: price range, wear value range, StatTrak, Souvenir, sticker presence
- Item search with autocomplete (SkinBaron API integration)
- View alert history with pagination, filtering, and sorting
- 2FA setup with QR code + recovery codes
- WebAuthn/Passkey registration and management
- OAuth account linking/unlinking (Google, Discord, GitHub)
- Profile management (username, email, password)
- Avatar upload (PNG/JPEG/WebP/GIF → WebP, 256px) with Gravatar fallback
- Security history (personal audit log viewer)
- GDPR data export (all personal data as JSON)
- Account self-deletion with identity verification

### Admin Features
- User approval/rejection system
- User list with pagination, sorting, and search
- Detailed user profile viewer
- Grant/revoke admin privileges (super admin only)
- Delete users (super admin only, cascade deletion)
- Account restrictions: temporary (auto-expiry) + permanent bans
- Sanction history with admin attribution
- Admin-forced username change
- Admin avatar removal
- Security audit log viewer (all users, filterable by event type and user)
- Admin action logs (super admin only, filterable by action type and admin)
- Global statistics dashboard
- System health monitoring (database, SkinBaron API, scheduler status)
- Force scheduler run

### System Features
- Automatic price polling (configurable cron schedule)
- Batch processing (10 rules in parallel)
- Discord rate limiting compliance (30 msg/min)
- Automatic audit log and alert cleanup (configurable retention)
- LRU user cache (500 entries, 30s TTL)
- Graceful shutdown (SIGTERM/SIGINT)
- Health checks (Docker-ready)
- Swagger/OpenAPI documentation (role-filtered: admins see all endpoints)

## 📦 Project Structure

```
skinbaron-alerts-sbapi/
├── backend/
│   ├── src/
│   │   ├── database/           # Database layer
│   │   │   ├── schema.ts       # 13 tables + 4 enums (Drizzle)
│   │   │   ├── schemas.ts      # Zod validation schemas
│   │   │   ├── repositories/   # Data access (users, rules, alerts, audit, webhooks, oauth, auth)
│   │   │   └── utils/          # Encryption utilities (AES-256-GCM)
│   │   ├── lib/                # Core services
│   │   │   ├── auth.ts         # JWT, bcrypt, zxcvbn, token management
│   │   │   ├── oauth.ts        # OAuth2 providers (Google, Discord, GitHub)
│   │   │   ├── csrf.ts         # CSRF double-submit cookie
│   │   │   ├── scheduler.ts    # Cron-based price polling
│   │   │   ├── notifier.ts     # Discord webhook notifications
│   │   │   ├── middleware.ts   # Auth middleware, rate limiting, IP extraction
│   │   │   └── webhook-validator.ts  # SSRF protection
│   │   ├── routes/             # API endpoints
│   │   │   ├── auth.ts         # Register, login, OAuth, passkey auth, 2FA verify
│   │   │   ├── user.ts         # Profile, 2FA, passkeys, avatar, data export
│   │   │   ├── admin.ts        # User management, sanctions, logs, stats
│   │   │   ├── rules.ts        # CRUD + batch operations
│   │   │   ├── alerts.ts       # History, filtering, stats
│   │   │   ├── webhooks.ts     # CRUD + batch operations
│   │   │   └── items.ts        # SkinBaron item search
│   │   └── types/
│   ├── drizzle/                # Database migrations
│   ├── Dockerfile
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── app/                # Next.js app router pages
│   │   │   ├── (dashboard)/    # Protected routes (alerts, rules, webhooks, settings, admin)
│   │   │   ├── login/          # Login page
│   │   │   ├── register/       # Registration page
│   │   │   ├── privacy/        # Privacy policy
│   │   │   └── tos/            # Terms of service
│   │   ├── components/         # React components (shadcn/ui based)
│   │   ├── contexts/           # Auth context
│   │   ├── hooks/              # Custom hooks (API mutations, debounce, etc.)
│   │   └── lib/                # API client, validation, formatters, constants
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml          # Orchestration (postgres + backend + frontend)
├── SECURITY.md                 # Security policy & architecture
└── LICENSE                     # MIT
```

## 🧪 API Documentation

Once running, access interactive API docs:
- **Swagger UI:** `http://localhost:8080/docs`
- **Authentication required:** Login first, then access /docs
- **Role-filtered:** Admins see all endpoints, users see their own

### Example API Calls

```bash
# Register new user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john","email":"john@example.com","password":"SecurePass123!"}'

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
# Backend & Frontend: 3 stages each
# Stage 1: Install production dependencies only
# Stage 2: Build TypeScript → JavaScript
# Stage 3: Minimal runtime (Node 22 Alpine + built files)
```

### Security Hardening

```yaml
# Applied to both backend and frontend containers
read_only: true              # Filesystem read-only
tmpfs: /tmp                  # Writable /tmp in memory
user: non-root (1001)        # No root privileges
cap_drop: ALL                # Drop all Linux capabilities
no-new-privileges: true      # Prevent privilege escalation
healthcheck: 30s interval    # Auto-restart if unhealthy
```

### Volumes

| Volume | Purpose |
|--------|---------|
| `skinbaron_postgres_data` | PostgreSQL data (external, persistent) |
| `skinbaron_avatar_data` | User avatar uploads |

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

| Optimization | Details |
|-------------|---------|
| **LRU Cache** | 500 users cached (30s TTL) |
| **Database Indexes** | 18+ indexes covering all query patterns |
| **Batch Operations** | Alert creation in transactions, 10 rules polled in parallel |
| **Connection Pool** | PostgreSQL async pool (max 20 connections) |
| **Code Splitting** | Next.js automatic code splitting + tree shaking |
| **Request Dedup** | React Query deduplication + background refetch |
| **Discord Compliance** | 30 msg/min rate limiting for webhook notifications |

## 🛠️ Troubleshooting

### "Authentication required to view API documentation"
→ Login first at `/login`, then access `/docs`

### "CSRF token missing"
→ Frontend auto-fetches token on init. Check browser console for errors.

### "Your account is awaiting admin approval"
→ First user is auto-approved as super admin. Others need admin approval.

### Docker volume permission issues
→ Ensure external volume exists:
```bash
docker volume create skinbaron_postgres_data
```

## 📝 License

MIT License — see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [SkinBaron](https://skinbaron.de) — CS2 marketplace API
- [Fastify](https://fastify.io) — Lightning-fast web framework
- [Next.js](https://nextjs.org) — React framework
- [shadcn/ui](https://ui.shadcn.com) — Component library
- [Drizzle ORM](https://orm.drizzle.team) — TypeScript ORM
- [SimpleWebAuthn](https://simplewebauthn.dev) — WebAuthn library

## 👤 Author

**Oswaaaald** — [42 School](https://42.fr/)

- GitHub: [@Oswaaaald](https://github.com/Oswaaaald)
- Portfolio: [oswaaaald.be](https://oswaaaald.be)

---

**⭐ Star this repo if you find it useful!**
