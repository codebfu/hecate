.PHONY: help prerequisites build test clean lint dev

NPM ?= npm

help:
	@echo "Hecate UI package targets:"
	@echo "  prerequisites  Install npm dependencies"
	@echo "  build          Build production bundle"
	@echo "  test           Run unit tests"
	@echo "  lint           Type-check without emit"
	@echo "  dev            Start Vite dev server"
	@echo "  clean          Remove build artifacts"

prerequisites:
	@echo "Installing UI npm dependencies..."
	@if [ -f package-lock.json ]; then $(NPM) ci; else $(NPM) install; fi

build: prerequisites
	@echo "Building UI package..."
	$(NPM) run build

test: prerequisites
	@echo "Testing UI package..."
	$(NPM) test

lint: prerequisites
	$(NPM) run lint

dev: prerequisites
	$(NPM) run dev

clean:
	rm -rf dist node_modules/.cache
