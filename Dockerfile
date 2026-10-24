
# syntax=docker/dockerfile:1

FROM oven/bun:1.4.4 AS deps

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --ignore-scripts --production

FROM oven/bun:1.4.4-slim AS runner

WORKDIR /app

RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

COPY --from=deps --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup package.json bun.lock ./
COPY --chown=appuser:appgroup index.ts ./
COPY --chown=appuser:appgroup src ./src
COPY --chown=appuser:appgroup public ./public
COPY --chown=appuser:appgroup scripts ./scripts
COPY --chown=appuser:appgroup docker-entrypoint.sh ./

# Pre-create certs dir owned by appuser so key generation works
RUN mkdir -p /app/certs && chown appuser:appgroup /app/certs && \
    chmod +x docker-entrypoint.sh

ENV NODE_ENV=production

EXPOSE 3000

USER appuser

ENTRYPOINT ["./docker-entrypoint.sh"]
