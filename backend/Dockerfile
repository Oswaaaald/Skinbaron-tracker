# Backend Dockerfile for SkinBaron Alerts
FROM node:22-alpine AS base

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Install all dependencies (including dev dependencies)
RUN npm ci

# Build the application
RUN npm run build

# Production image, copy all the files and run the app
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

# Create a non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 skinbaron-alerts

# Create data directory for SQLite database
RUN mkdir -p /app/data && chown skinbaron-alerts:nodejs /app/data

# Copy the built application
COPY --from=builder --chown=skinbaron-alerts:nodejs /app/dist ./dist
COPY --from=builder --chown=skinbaron-alerts:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=skinbaron-alerts:nodejs /app/package.json ./package.json

# Switch to non-root user
USER skinbaron-alerts

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "const http = require('http'); \
  const options = { host: 'localhost', port: 8080, path: '/health', timeout: 2000 }; \
  const req = http.request(options, (res) => { \
    if (res.statusCode === 200) process.exit(0); \
    else process.exit(1); \
  }); \
  req.on('error', () => process.exit(1)); \
  req.end();"

# Start the application
CMD ["node", "dist/index.js"]