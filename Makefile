.PHONY: build run test fmt lint brew-up brew-down brew-status docker-up docker-down docker-build migrate perf security-audit helm-template verify-production

build:
	cargo build -p authsvc-server

run: brew-up
	cargo run -p authsvc-server

test: brew-up
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

perf:
	./scripts/perf_test.sh

security-audit:
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked
	cargo audit

helm-template:
	helm template authsvc deploy/helm/authsvc \
		-f deploy/helm/authsvc/values-prod.yaml \
		--set secrets.jwtPublicKeyPem="dummy" \
		--set secrets.jwtPrivateKeyPem="dummy" \
		--set secrets.databaseUrl="postgres://authsvc_app@postgres:5432/authsvc" \
		--set secrets.redisUrl="redis://redis:6379" \
		--set secrets.dataEncryptionKey="01234567890123456789012345678901" \
		--set secrets.bootstrapSecret="bootstrap" \
		--set secrets.metricsBearerToken="metrics-token" \
		--set env.ALLOWED_ORIGINS="https://app.example.com"

verify-production:
	@test -n "$$AUTHSVC_URL" || (echo "Set AUTHSVC_URL (e.g. https://auth.example.com)" && exit 1)
	@chmod +x scripts/verify_production.sh
	@./scripts/verify_production.sh

# Default local deps: Homebrew Postgres + Redis (no Docker)
brew-up:
	@./scripts/brew_services.sh up

brew-down:
	@./scripts/brew_services.sh down

brew-status:
	@./scripts/brew_services.sh status

# Optional: Docker Compose (not required for local dev)
docker-up:
	docker compose up -d postgres redis

docker-down:
	docker compose down

docker-build:
	docker compose build authsvc

migrate:
	@echo "Migrations run automatically on server start"
