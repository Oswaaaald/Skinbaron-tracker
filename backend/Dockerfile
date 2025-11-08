# Backend Dockerfile for SkinBaron Alerts  
FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app
# Install build dependencies for better-sqlite3 and clean up in same layer
RUN apk add --no-cache --virtual .build-deps python3 make g++ sqlite-dev libc6-compat

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && apk del .build-deps

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
# Install build dependencies, copy files, build and clean up in optimized layers
RUN apk add --no-cache --virtual .build-deps python3 make g++ sqlite-dev libc6-compat
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Install dev dependencies, build and clean up
RUN npm ci && npm run build && apk del .build-deps

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