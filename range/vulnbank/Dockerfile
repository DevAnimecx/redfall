# vulnbank — deliberately vulnerable banking API (Redfall range target).
# Build stage
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Runtime stage
FROM node:20-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
RUN mkdir -p /app/uploads
EXPOSE 4000
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=12 \
  CMD curl -fsS http://127.0.0.1:4000/health || exit 1
CMD ["node", "dist/server.js"]
