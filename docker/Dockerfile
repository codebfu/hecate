# syntax=docker/dockerfile:1

ARG HECATE_VERSION=1.0.0

FROM rust:1.93-bookworm AS rust
ARG HECATE_VERSION
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN sed -i "s/^version = \".*\"/version = \"${HECATE_VERSION}\"/" Cargo.toml \
    && cargo build --release -p hecate-api

FROM node:24-bookworm-slim AS ui
ARG HECATE_VERSION
WORKDIR /app/packages/ui
COPY packages/ui/package.json packages/ui/package-lock.json ./
RUN npm ci
COPY packages/ui/ ./
RUN sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${HECATE_VERSION}\"/" package.json \
    && npm run build

FROM node:24-bookworm-slim AS mcp
ARG HECATE_VERSION
WORKDIR /app/packages/mcp
COPY packages/mcp/package.json packages/mcp/package-lock.json ./
RUN npm ci
COPY packages/mcp/ ./
RUN sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${HECATE_VERSION}\"/" package.json \
    && npm run build

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 hecate \
    && useradd -u 1000 -g hecate -m -s /usr/sbin/nologin hecate
WORKDIR /opt/hecate
COPY --from=rust /app/target/release/hecate-api /usr/local/bin/hecate-api
COPY --from=rust /app/migrations ./migrations
COPY --from=ui /app/packages/ui/dist ./ui/dist
COPY --from=mcp /app/packages/mcp/dist ./mcp/dist
COPY --from=mcp /app/packages/mcp/resources ./mcp/resources
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && chown -R hecate:hecate /opt/hecate
USER hecate
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM node:24-bookworm-slim AS mcp-runtime
WORKDIR /opt/hecate/mcp
COPY packages/mcp/package.json packages/mcp/package-lock.json ./
RUN npm ci --omit=dev
COPY --from=mcp /app/packages/mcp/dist ./dist
COPY --from=mcp /app/packages/mcp/resources ./resources
USER node
EXPOSE 3100
CMD ["node", "dist/index.js"]
