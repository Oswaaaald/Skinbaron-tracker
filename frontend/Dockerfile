# syntax=docker/dockerfile:1.7

# ================================
# Frontend Dockerfile (HARDENED)
# ================================

FROM node:22-alpine AS base
ARG NPM_VERSION=11.12.1
RUN apk add --no-cache ca-certificates \
    && npm install -g "npm@${NPM_VERSION}"

FROM base AS builder
WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* frontend/.npmrc ./frontend/
COPY packages/contracts ./packages/contracts

WORKDIR /app/frontend
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --fund=false
RUN rm -rf node_modules/@skinbaron/contracts \
    && mkdir -p node_modules/@skinbaron \
    && cp -R /app/packages/contracts node_modules/@skinbaron/contracts

COPY frontend ./

ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

ARG NEXT_PUBLIC_SENTRY_DSN
ENV NEXT_PUBLIC_SENTRY_DSN=$NEXT_PUBLIC_SENTRY_DSN

ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_BUILD_TURBO=1

# Validate required build arguments
RUN node scripts/validate-env.js

RUN --mount=type=cache,target=/app/frontend/.next/cache \
    npm run build

# ---------- runner ----------
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Non-root user
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

# Copy build output (READ-ONLY at runtime)
COPY --from=builder /app/frontend/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/frontend/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/frontend/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/packages/contracts ./packages/contracts

# Ensure Next.js image cache dir exists and is writable
RUN mkdir -p /app/.next/cache/images && chown nextjs:nodejs /app/.next/cache/images

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
