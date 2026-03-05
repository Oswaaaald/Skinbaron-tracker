# SkinBaron Tracker

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js&logoColor=white)](https://nextjs.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5-white?logo=fastify&logoColor=black)](https://fastify.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A self-hosted SkinBaron alerting stack (Fastify API + Next.js frontend) for CS2 skins.
Create rules with price, wear, and badge filters, then receive Discord notifications when a matching item appears.

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
| **Database** | PostgreSQL (Drizzle ORM schema + SQL migrations) |
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

### 3. Deploy

```bash
docker compose up -d --build
```

The app starts at `http://localhost:3000` (frontend) and `http://localhost:8080` (API).

The first registered user is automatically approved as **super admin**.

---

## Environment Variables

### Required / Common

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | - | PostgreSQL connection string |
| `JWT_SECRET` | ✅ | - | Base JWT signing key (min 32 chars) |
| `ENCRYPTION_KEY` | ✅ (prod) | `JWT_SECRET` (non-production) | AES-256-GCM key for sensitive data |
| `CORS_ORIGIN` | ✅ | - | Frontend origin (CORS + WebAuthn derivation) |
| `NEXT_PUBLIC_API_URL` | ✅ | - | Public API base URL used by frontend |
| `NODE_ENV` | — | `development` | `development`, `production`, `test` |
| `PORT` | — | `8080` | Backend listen port |
| `TRUST_PROXY_HOPS` | — | `0` | Number of trusted proxy hops |
| `DATABASE_SSL` | — | `false` | Enable PostgreSQL SSL |
| `DATABASE_SSL_REJECT_UNAUTHORIZED` | — | `true` | Verify PostgreSQL certificate chain |
| `POLL_CRON` | — | `*/5 * * * *` | Scheduler cron expression |
| `SCHEDULER_ENABLED` | — | `true` | Enables automatic polling |
| `RATE_LIMIT_MAX` | — | `1000` | Requests per rate-limit window |
| `RATE_LIMIT_WINDOW` | — | `60000` | Rate-limit window in ms |
| `LOG_LEVEL` | — | `info` | `error` \| `warn` \| `info` \| `debug` |
| `AUDIT_LOG_RETENTION_DAYS` | — | `365` | Audit log retention policy |
| `ALERT_RETENTION_DAYS` | — | `90` | Alert retention policy |

### Optional Integrations

- OAuth2: `GOOGLE_*`, `GITHUB_*`, `DISCORD_*`
- Passkeys overrides: `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_RP_ORIGIN`
- Monitoring: `SENTRY_DSN`, `NEXT_PUBLIC_SENTRY_DSN`
- Notifications branding: `DISCORD_BOT_NAME`, `DISCORD_BOT_AVATAR`
- Product metadata: `APP_VERSION`, `SB_API_KEY`, `COOKIE_DOMAIN`

For the full validated list and defaults, see [.env.example](.env.example) and [backend/src/lib/config.ts](backend/src/lib/config.ts).

---

## Project Structure

```
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile              # Multi-stage Node 22 Alpine build
│   ├── drizzle/                # SQL migrations
│   ├── drizzle.config.ts
│   └── src/
│       ├── index.ts            # Fastify server setup
│       ├── database/
│       │   ├── schema.ts       # Drizzle table + enum definitions
│       │   ├── connection.ts   # PostgreSQL pool + Drizzle
│       │   ├── index.ts        # Store facade
│       │   └── repositories/   # data access by domain
│       ├── lib/
│       │   ├── auth.ts         # JWT, encryption, OAuth crypto
│       │   ├── config.ts       # Zod-validated env config
│       │   ├── middleware.ts   # Auth, RBAC, CSRF, cookie helpers
│       │   ├── notifier.ts     # Discord webhook with retry
│       │   ├── scheduler.ts    # Cron-based price poller
│       │   └── ...
│       ├── routes/             # module registries + domain subroutes
│       └── types/
└── frontend/
    ├── Dockerfile              # Multi-stage Next.js standalone build
    └── src/
        ├── app/                # Next.js App Router pages
        ├── components/
        │   ├── admin/          # admin panel, logs, user detail
        │   ├── alerts/         # alerts grid + filters
        │   ├── auth/           # auth form + 2FA setup
        │   ├── profile/        # profile settings + security
        │   ├── rules/          # rules dialog + table
        │   ├── webhooks/       # webhook table
        │   ├── system/         # system stats
        │   └── ui/             # shared UI primitives
        ├── contexts/           # Auth context
        ├── hooks/              # shared React hooks
        └── lib/                # API client, utils, validation
```

---

## API Overview

Current route domains:

| Module | Prefix | Access |
|---|---|---|
| Auth | `/api/auth` | Public + authenticated |
| User | `/api/user` | Authenticated |
| Rules | `/api/rules` | Authenticated |
| Alerts | `/api/alerts` | Authenticated |
| Webhooks | `/api/webhooks` | Authenticated |
| Items | `/api/items` | Authenticated |
| Admin | `/api/admin` | Admin / Super Admin |
| System | `/api/*` | Public / mixed |

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
npm ci
npm run dev          # ts watch mode

# Frontend
cd frontend
npm ci
npm run dev          # Next.js dev server

# Database migrations
cd backend
npx drizzle-kit generate   # Generate migration from schema changes
npx drizzle-kit migrate    # Apply migrations

# Quality gates
cd backend && npm run build && npm run lint
cd ../frontend && npm run build && npm run lint
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
- PostgreSQL managed externally (not in compose)

---

## License

[MIT](LICENSE) - Copyright (c) 2025-2026 Oswaaaald and contributors
