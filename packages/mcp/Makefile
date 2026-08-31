.PHONY: help prerequisites build test clean lint dev

NPM ?= npm

help:
	@echo "Hecate MCP package targets:"
	@echo "  prerequisites  Install npm dependencies"
	@echo "  build          Compile TypeScript"
	@echo "  test           Run unit tests"
	@echo "  lint           Type-check without emit"
	@echo "  dev            Start dev server with hot reload"
	@echo "  clean          Remove build artifacts"

prerequisites:
	@echo "Installing MCP npm dependencies..."
	@if [ -f package-lock.json ]; then $(NPM) ci; else $(NPM) install; fi

build: prerequisites
	@echo "Building MCP package..."
	$(NPM) run build

test: prerequisites
	@echo "Testing MCP package..."
	$(NPM) test

lint: prerequisites
	$(NPM) run lint

dev: prerequisites
	$(NPM) run dev

clean:
	rm -rf dist node_modules/.cache
