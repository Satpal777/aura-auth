
# syntax=docker/dockerfile:1

FROM oven/bun:1.4.4 AS deps

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --ignore-scripts --production

FROM oven/bun:1.4.4-slim AS runner

WORKDIR /app

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

COPY --from=deps --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup package.json bun.lock ./
COPY --chown=appuser:appgroup index.ts ./
COPY --chown=appuser:appgroup src ./src
COPY --chown=appuser:appgroup public ./public

ENV NODE_ENV=production

EXPOSE 3000

USER appuser

CMD ["bun", "index.ts"]
