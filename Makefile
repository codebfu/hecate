.PHONY: help prerequisites build test clean lint dev-api dev-ui dev-mcp dev docker-build docker-up docker-down migrate

CARGO ?= cargo
NPM ?= npm
COMPOSE ?= docker compose -f docker/docker-compose.yml
DATABASE_URL ?= postgres://hecate:hecate@localhost:5432/hecate

help:
	@echo "Hecate server targets:"
	@echo "  prerequisites  Install Rust and npm dependencies"
	@echo "  build          Build Rust API, MCP, and UI packages"
	@echo "  test           Run Rust and npm test suites"
	@echo "  lint           Run clippy and npm lint"
	@echo "  clean          Remove build artifacts"
	@echo "  dev-api        Run API locally (auto-migrates on start)"
	@echo "  dev-ui         Run UI Vite dev server"
	@echo "  dev-mcp        Run MCP dev server"
	@echo "  docker-build   Build Docker images (api + mcp)"
	@echo "  docker-up      Start docker compose stack"
	@echo "  docker-down    Stop docker compose stack"
	@echo "  migrate        Apply SQLx migrations via sqlx-cli"

prerequisites:
	@echo "Checking Rust toolchain..."
	@command -v $(CARGO) >/dev/null || (echo "Rust/cargo not found" && exit 1)
	@echo "Fetching Rust dependencies..."
	-$(CARGO) fetch
	@echo "Installing MCP npm dependencies..."
	$(MAKE) -C packages/mcp prerequisites NPM=$(NPM)
	@echo "Installing UI npm dependencies..."
	$(MAKE) -C packages/ui prerequisites NPM=$(NPM)

build: prerequisites
	@echo "Building Rust workspace..."
	-$(CARGO) build --release
	@echo "Building MCP package..."
	$(MAKE) -C packages/mcp build NPM=$(NPM)
	@echo "Building UI package..."
	$(MAKE) -C packages/ui build NPM=$(NPM)

test: prerequisites
	cargo test
	$(MAKE) -C packages/mcp test NPM=$(NPM)
	$(MAKE) -C packages/ui test NPM=$(NPM)

lint: prerequisites
	-$(CARGO) clippy -- -D warnings
	$(MAKE) -C packages/mcp lint NPM=$(NPM)
	$(MAKE) -C packages/ui lint NPM=$(NPM)

clean:
	-$(CARGO) clean
	$(MAKE) -C packages/mcp clean
	$(MAKE) -C packages/ui clean

dev-ui:
	$(MAKE) -C packages/ui dev NPM=$(NPM)

dev-mcp:
	$(MAKE) -C packages/mcp dev NPM=$(NPM)

dev-api:
	DATABASE_URL=$(DATABASE_URL) $(CARGO) run --bin hecate-api

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up -d

docker-down:
	$(COMPOSE) down

migrate:
	@command -v sqlx >/dev/null || (echo "Install sqlx-cli: cargo install sqlx-cli --no-default-features --features rustls,postgres" && exit 1)
	sqlx migrate run --source migrations --database-url "$(DATABASE_URL)"
