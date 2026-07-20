.PHONY: build run test fmt lint brew-up brew-down brew-status docker-up docker-down docker-build migrate

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
