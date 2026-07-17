.PHONY: build run test fmt lint docker-up docker-down migrate

build:
	cargo build -p authsvc-server

run:
	cargo run -p authsvc-server

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

docker-up:
	docker compose up -d postgres redis

docker-down:
	docker compose down

docker-build:
	docker compose build authsvc

migrate:
	@echo "Migrations run automatically on server start"
