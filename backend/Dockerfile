# ================================
# Backend Dockerfile (HARDENED)
# ================================

FROM node:22-alpine AS base

RUN apk update && apk add --no-cache ca-certificates && \
    npm install -g npm@11.8.0

# ---------- deps ----------
FROM base AS deps
WORKDIR /app

RUN apk add --no-cache --virtual .build-deps \
    python3 make g++ sqlite-dev libc6-compat

COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev && apk del .build-deps

# ---------- builder ----------
FROM base AS builder
WORKDIR /app

RUN apk add --no-cache --virtual .build-deps \
    python3 make g++ sqlite-dev libc6-compat

COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .
RUN npm run build && apk del .build-deps

# ---------- runner ----------
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 skinbaron

RUN mkdir -p /app/data && chown skinbaron:nodejs /app/data

COPY --from=builder --chown=skinbaron:nodejs /app/dist ./dist
COPY --from=builder --chown=skinbaron:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=skinbaron:nodejs /app/package.json ./package.json
COPY --from=builder --chown=skinbaron:nodejs /app/scripts ./scripts

USER skinbaron

EXPOSE 8080

# Validate environment variables at container startup
ENTRYPOINT ["sh", "-c", "node scripts/validate-env.js && exec node dist/index.js"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"
