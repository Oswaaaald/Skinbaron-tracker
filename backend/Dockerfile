# syntax=docker/dockerfile:1.7

# ================================
# Backend Dockerfile (HARDENED)
# ================================

FROM node:22-alpine AS base
RUN apk add --no-cache ca-certificates

FROM base AS builder
WORKDIR /app

COPY backend/package.json backend/package-lock.json* ./backend/
COPY packages/contracts ./packages/contracts

WORKDIR /app/backend
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --fund=false

COPY backend ./
RUN npm run build && npm prune --omit=dev

# ---------- runner ----------
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 skinbaron \
    && mkdir -p /data/avatars \
    && chown skinbaron:nodejs /data/avatars

COPY --from=builder --chown=skinbaron:nodejs /app/backend/node_modules ./node_modules
COPY --from=builder --chown=skinbaron:nodejs /app/backend/dist ./dist
COPY --from=builder --chown=skinbaron:nodejs /app/backend/drizzle ./drizzle
COPY --from=builder --chown=skinbaron:nodejs /app/backend/package.json ./package.json
COPY --from=builder --chown=skinbaron:nodejs /app/backend/scripts ./scripts
COPY --from=builder --chown=skinbaron:nodejs /app/packages/contracts ./packages/contracts

USER skinbaron

EXPOSE 8080

# Validate environment variables at container startup
ENTRYPOINT ["sh", "-c", "node scripts/validate-env.js && exec node dist/index.js"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "const req=require('http').get('http://127.0.0.1:8080/api/health',res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>{try{const json=JSON.parse(body);process.exit(res.statusCode===200&&json.database==='healthy'?0:1);}catch{process.exit(1);}})});req.on('error',()=>process.exit(1));"
