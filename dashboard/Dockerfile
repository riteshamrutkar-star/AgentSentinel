# ==============================================================================
# AgentSentinel — Production Dashboard Dockerfile (Phase 0.8)
# Multi-stage, Node 20 builder + lightweight Nginx alpine server
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Frontend Assets
# ------------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies with lockfile caching
COPY package.json package-lock.json ./
RUN npm ci

# Copy source code and build production bundles
COPY . .
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Minimal Nginx Runtime
# ------------------------------------------------------------------------------
FROM nginx:alpine AS runtime

# Remove default nginx static assets and configuration
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy custom dashboard nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/healthz || exit 1

# Run nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
