# syntax=docker/dockerfile:1
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci || npm install

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
# Healthcheck tool
RUN apk add --no-cache curl
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Run as non-root
USER node
EXPOSE 8000
# Healthcheck: wait a bit for app to boot, then probe /healthz
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=10 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
CMD ["node", "app.js"]
