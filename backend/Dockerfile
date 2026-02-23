# ================================
# Backend Dockerfile (HARDENED)
# ================================

FROM node:22-alpine AS base

RUN apk update && apk add --no-cache ca-certificates && \
    npm install -g npm@11.10.1

# ---------- deps ----------
FROM base AS deps
WORKDIR /app

COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev

# ---------- builder ----------
FROM base AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .
RUN npm run build

# ---------- runner ----------
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 skinbaron \
    && mkdir -p /data/avatars \
    && chown skinbaron:nodejs /data/avatars

COPY --from=deps --chown=skinbaron:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=skinbaron:nodejs /app/dist ./dist
COPY --from=builder --chown=skinbaron:nodejs /app/drizzle ./drizzle
COPY --from=builder --chown=skinbaron:nodejs /app/package.json ./package.json
COPY --from=builder --chown=skinbaron:nodejs /app/scripts ./scripts

USER skinbaron

EXPOSE 8080

# Validate environment variables at container startup
ENTRYPOINT ["sh", "-c", "node scripts/validate-env.js && exec node dist/index.js"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:8080/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"
