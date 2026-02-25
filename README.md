# SkinBaron Tracker

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js&logoColor=white)](https://nextjs.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5-white?logo=fastify&logoColor=black)](https://fastify.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A self-hosted price tracker for [SkinBaron](https://skinbaron.de) CS2 skins. Create rules with price, wear, and badge filters — get notified on Discord when a matching item appears.

---

## Features

### Core
- **Price monitoring** — Automatic polling via configurable cron schedule (default: every 5 min)
- **Advanced rule filters** — Price range, wear range, StatTrak™, Souvenir, Stickers
- **Discord webhooks** — Compact or detailed notification embeds with retry + exponential backoff
- **Alert history** — Filterable (by rule, item name, wear, badges), sortable, paginated
- **Item search** — Autocomplete powered by SkinBaron API

### Authentication
- Email/password with bcrypt (12 rounds) + zxcvbn strength validation
- JWT with separate access/refresh signing keys and token rotation
- TOTP 2-Factor Authentication with QR code setup and 10 recovery codes
- WebAuthn / Passkeys (FIDO2) — register up to 10, auto-detects device name
- OAuth2: Google, Discord, GitHub (PKCE) — with account linking/unlinking
- OAuth 2FA flow (cookie-encrypted pending state → TOTP verification)

### Security
- AES-256-GCM encryption for secrets (webhook URLs, TOTP, recovery codes)
- CSRF double-submit cookie pattern with constant-time comparison
- SSRF protection on webhooks (domain allowlist, DNS resolution, private IP blocking)
- Avatar validation (magic bytes, sharp re-encoding to WebP 256px, EXIF stripping)
- Access token blacklisting on logout/password change
- Timing-safe comparison everywhere + fake bcrypt for non-existent users
- Pending challenges stored in PostgreSQL (survives restarts, no in-memory state)

### Admin Panel (3-tier RBAC: user → admin → super admin)
- User management: list, search, approve/reject, restrict/unrestrict, delete
- Account restrictions: temporary (auto-expiry) + permanent with email ban
- Sanction history with admin attribution
- Admin-forced username change, avatar removal
- Security audit logs (all users, filterable by event type)
- Admin action logs (super admin only)
- Global stats dashboard, system health, force scheduler run

### GDPR Compliance
- Data export (Art. 20 — all personal data as JSON)
- Account self-deletion with identity verification
- Configurable audit log retention (default: 365 days)
- Alert retention cleanup (default: 90 days)
- Cookie consent banner

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Next.js 16, React 19, TanStack Query 5, Tailwind CSS v4, shadcn/ui, Radix UI |
| **Backend** | Fastify 5, Drizzle ORM 0.45, Zod v4, Pino logger |
| **Database** | PostgreSQL 17 (14 tables, 9 migrations) |
| **Auth** | JWT (jsonwebtoken), bcrypt, otplib (TOTP), @simplewebauthn/server, arctic (OAuth) |
| **Infra** | Docker Compose, multi-stage builds, read-only containers, non-root users |

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- A [SkinBaron API key](https://skinbaron.de)
- (Optional) OAuth2 credentials for Google, Discord, GitHub

### 1. Clone

```bash
git clone https://github.com/Oswaaaald/Skinbaron-tracker.git
cd Skinbaron-tracker
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your values (see Environment Variables below)
```

### 3. Create the database volume

```bash
docker volume create skinbaron_postgres_data
```

### 4. Deploy

```bash
docker compose up -d --build
```

The app starts at `http://localhost:3000` (frontend) and `http://localhost:8080` (API).

The first registered user is automatically approved as **super admin**.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `JWT_SECRET` | ✅ | — | JWT signing key (min 32 chars) |
| `JWT_ACCESS_SECRET` | — | `JWT_SECRET` | Separate access token key |
| `JWT_REFRESH_SECRET` | — | `JWT_SECRET` | Separate refresh token key |
| `ENCRYPTION_KEY` | ✅ prod | — | AES-256-GCM key (must differ from JWT_SECRET) |
| `CORS_ORIGIN` | ✅ | — | Frontend URL (e.g. `https://tracker.example.com`) |
| `NEXT_PUBLIC_API_URL` | ✅ | — | API base URL (e.g. `https://api.example.com`) |
| `COOKIE_DOMAIN` | — | — | Cookie domain |
| `SB_API_KEY` | — | — | SkinBaron API key |
| `NODE_ENV` | — | `production` | Environment |
| `PORT` | — | `8080` | Backend port |
| `DATABASE_SSL` | — | `false` | Enable PostgreSQL SSL |
| `POLL_CRON` | — | `*/5 * * * *` | Polling schedule (cron) |
| `SCHEDULER_ENABLED` | — | `true` | Enable automatic polling |
| `RATE_LIMIT_MAX` | — | `1000` | Requests per window |
| `RATE_LIMIT_WINDOW` | — | `60000` | Rate limit window (ms) |
| `LOG_LEVEL` | — | `info` | `error` \| `warn` \| `info` \| `debug` |
| `AUDIT_LOG_RETENTION_DAYS` | — | `365` | Audit log retention |
| `ALERT_RETENTION_DAYS` | — | `90` | Alert retention |
| `APP_VERSION` | — | `dev` | Displayed version |
| **OAuth2 (optional)** | | | |
| `GOOGLE_CLIENT_ID` | — | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | — | — | Google OAuth secret |
| `GITHUB_CLIENT_ID` | — | — | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | — | — | GitHub OAuth secret |
| `DISCORD_CLIENT_ID` | — | — | Discord OAuth client ID |
| `DISCORD_CLIENT_SECRET` | — | — | Discord OAuth secret |

---

## Project Structure

```
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile              # Multi-stage Node 22 Alpine build
│   ├── drizzle/                # SQL migrations (0000–0008)
│   ├── drizzle.config.ts
│   └── src/
│       ├── index.ts            # Fastify server setup
│       ├── database/
│       │   ├── schema.ts       # 14 tables, 4 enums
│       │   ├── connection.ts   # PostgreSQL pool + Drizzle
│       │   ├── index.ts        # Store facade
│       │   └── repositories/   # 9 repositories
│       ├── lib/
│       │   ├── auth.ts         # JWT, encryption, OAuth crypto
│       │   ├── config.ts       # Zod-validated env config
│       │   ├── middleware.ts   # Auth, RBAC, CSRF, cookie helpers
│       │   ├── notifier.ts    # Discord webhook with retry
│       │   ├── scheduler.ts   # Cron-based price poller
│       │   └── ...
│       ├── routes/             # 7 route modules (65 endpoints)
│       └── types/
└── frontend/
    ├── Dockerfile              # Multi-stage Next.js standalone build
    └── src/
        ├── app/                # Next.js App Router pages
        ├── components/         # 21 custom + 26 UI (shadcn)
        ├── contexts/           # Auth context
        ├── hooks/              # 7 custom hooks
        └── lib/                # API client, utils, validation
```

---

## API Overview

**65 endpoints** across 7 route modules:

| Module | Prefix | Endpoints | Auth |
|---|---|---|---|
| Auth | `/api/auth` | 12 | Mostly public |
| User | `/api/user` | 22 | Authenticated |
| Rules | `/api/rules` | 7 | Authenticated |
| Alerts | `/api/alerts` | 4 | Authenticated |
| Webhooks | `/api/webhooks` | 7 | Authenticated |
| Items | `/api/items` | 1 | Authenticated |
| Admin | `/api/admin` | 18 | Admin / Super Admin |

Full API docs available at `/api/docs` (Swagger UI, role-filtered).

---

## Limits

| Resource | Limit |
|---|---|
| Rules per user | 50 |
| Webhooks per user | 20 |
| Passkeys per user | 10 |
| Avatar file size | 5 MB |
| Avatar output | WebP, 256 × 256 px |
| DB connection pool | 20 |
| Auth rate limit | 5 req/min per IP |
| Global rate limit | 1000 req/min per IP (configurable) |

---

## Development

```bash
# Backend
cd backend
npm install
npm run dev          # ts watch mode

# Frontend
cd frontend
npm install
npm run dev          # Next.js dev server

# Database migrations
cd backend
npx drizzle-kit generate   # Generate migration from schema changes
npx drizzle-kit migrate    # Apply migrations
```

---

## Docker Hardening

Both application containers run with:
- `read_only: true` filesystem
- `cap_drop: ALL`
- `security_opt: no-new-privileges:true`
- Non-root user (UID 1001)
- Tmpfs for `/tmp`
- Health checks (30s interval)
- PostgreSQL exposed only on `127.0.0.1`

---

## License

[MIT](LICENSE) — Copyright © 2025–2026 Oswaaaald
