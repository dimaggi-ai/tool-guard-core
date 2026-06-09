# Tool Guard Core — make targets
#
# Single binary, no external services. Every target should run on a
# clean checkout with only `go` installed.

GO      ?= go
BIN     ?= bin
PKGS    := ./pkg/... ./cmd/...

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build all binaries into ./bin (tg, tg-proxy, battle-test, example-chain)
	@mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -o $(BIN)/tg ./cmd/tg
	CGO_ENABLED=0 $(GO) build -o $(BIN)/tg-proxy ./cmd/tg-proxy
	CGO_ENABLED=0 $(GO) build -o $(BIN)/battle-test ./cmd/battle-test
	CGO_ENABLED=0 $(GO) build -o $(BIN)/example-chain ./cmd/example-chain

.PHONY: sample
sample: build ## Run the hand-coded sample app (refund-tool + tg-proxy + Go agent)
	@bash examples/sample-app/run.sh

.PHONY: sample-ollama
sample-ollama: build ## Run the real-LLM demo (Ollama gemma4 drives the agent through tg-proxy)
	@$(GO) build -o $(BIN)/ollama-agent ./examples/ollama-agent
	@$(GO) build -o $(BIN)/sample-tool ./examples/sample-app/tool
	@bash examples/ollama-agent/run.sh

.PHONY: sample-postgres
sample-postgres: ## Run the dockerized Postgres demo (gemma4 attacks a real DB, proxy denies)
	@cd examples/postgres-attack && docker compose up --build

.PHONY: sample-postgres-down
sample-postgres-down: ## Stop the Postgres demo and remove its volumes
	@cd examples/postgres-attack && docker compose down -v

.PHONY: test-postgres
test-postgres: ## End-to-end policy test: bring up backends, run 28 curl assertions, tear down
	@cd examples/postgres-attack && bash -c '\
	set -e; \
	trap "docker compose down -v >/dev/null 2>&1" EXIT; \
	echo "→ building + starting postgres / tg-proxy / db-tool / os-tool…"; \
	docker compose up -d --build postgres tg-proxy db-tool os-tool >/dev/null; \
	echo "→ waiting for tg-proxy /healthz…"; \
	for i in $$(seq 1 20); do \
	  if curl -fs http://127.0.0.1:19090/healthz >/dev/null 2>&1; then echo "  proxy ready"; break; fi; \
	  sleep 1; \
	done; \
	echo "→ running test-policies.sh (28 deterministic assertions)…"; \
	bash test-policies.sh'

.PHONY: test-finance
test-finance: build ## Prove the CFO finance policies block over-cap spend / wires / velocity (18 assertions, no Docker/LLM)
	@bash examples/run-deterministic-suite.sh finance-cfo

.PHONY: test-business
test-business: build ## Prove the business-ops policies block PII export / mass-comms / credit abuse (26 assertions, no Docker/LLM)
	@bash examples/run-deterministic-suite.sh business-ops

.PHONY: test-postgres-full
test-postgres-full: build ## Prove SQL + shell + path protection: 28 deterministic + 45 + 56 adversarial, zero bypasses (needs Docker)
	@bash examples/postgres-attack/run-all-suites.sh

.PHONY: test-policies
test-policies: test-finance test-business sample ## Run all no-Docker policy-protection suites (finance + business-ops + sample-app)

.PHONY: test
test: ## Run unit + golden tests with the race detector
	$(GO) test -race -count=1 $(PKGS)

.PHONY: integration
integration: build ## Run shell-level integration tests (CLI + tg-proxy HTTP)
	$(GO) test -race -count=1 -tags=integration ./cmd/tg/... ./cmd/tg-proxy/...

.PHONY: cover
cover: ## Statement coverage per package
	$(GO) test -cover -count=1 $(PKGS)

.PHONY: cover-html
cover-html: ## Generate per-statement HTML coverage report at coverage.html
	$(GO) test -coverprofile=coverage.out -count=1 $(PKGS)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html in your browser"

.PHONY: bench
bench: ## Run microbenchmarks in pkg/engine
	$(GO) test -bench=. -benchmem -count=1 ./pkg/engine/

.PHONY: lint
lint: ## Run go vet across all packages
	$(GO) vet $(PKGS)

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf $(BIN) coverage.out coverage.html
