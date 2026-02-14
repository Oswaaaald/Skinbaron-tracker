# ================================
# Frontend Dockerfile (HARDENED)
# ================================

FROM node:22-alpine AS base

RUN apk update && apk add --no-cache ca-certificates && \
    npm install -g npm@11.10.0

# ---------- builder ----------
FROM base AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY . .

ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_BUILD_TURBO=1

# Validate required build arguments
RUN node scripts/validate-env.js

RUN --mount=type=cache,target=/app/.next/cache \
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
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -T 3 -q -O /dev/null http://127.0.0.1:3000/

CMD ["node", "server.js"]
