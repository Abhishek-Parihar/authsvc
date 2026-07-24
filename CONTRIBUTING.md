# Contributing to authsvc

Thank you for your interest in contributing. This project welcomes bug reports, documentation improvements, tests, and feature work that fits the [project scope](README.md#scope).

## Getting started

### Prerequisites

- Rust stable (`rustup default stable`)
- PostgreSQL 16+ and Redis 7+
- Optional: Docker (for testcontainers fallback when Homebrew services are unavailable)

### Local setup

```bash
git clone https://github.com/Abhishek-Parihar/authsvc.git
cd authsvc
cp .env.example .env
make brew-up    # or: docker compose up -d postgres redis
cargo run -p authsvc-server
```

The server runs migrations on startup. Integration tests expect Postgres and Redis — `make test` starts Homebrew services when available.

### Before you open a PR

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace -- --test-threads=1
```

For TypeScript SDK changes:

```bash
cd sdk/typescript && npm install && npm run build
```

## Pull request guidelines

1. **One concern per PR** — keep changes focused and reviewable.
2. **Add or update tests** for behavior changes, especially auth flows and security-sensitive code.
3. **Update docs** when changing configuration, API surface (`api/openapi.yaml`), or deployment behavior.
4. **No secrets** — never commit `.env`, keys, or real credentials.
5. **Describe the why** — explain the problem and approach in the PR description.

## Code style

- Follow existing patterns in the crate you are editing.
- Prefer extending ports/traits in `authsvc-core` over coupling handlers to Postgres.
- Use `AuthError` variants appropriately; avoid leaking internal details in public API responses.
- Security-sensitive paths (crypto, token handling, SAML) deserve extra tests and comments only where non-obvious.

## Project structure

| Crate / path | Role |
|--------------|------|
| `crates/authsvc-core` | Domain types and repository ports |
| `crates/authsvc-server` | HTTP API, stores, services |
| `crates/authsvc-idp` | Federated identity providers |
| `crates/authsvc-policy` | RBAC, Casbin, OpenFGA evaluators |
| `crates/authsvc-client` | Rust JWKS validator |
| `migrations/` | SQL schema (numbered, reversible pairs) |
| `api/openapi.yaml` | Public API contract |
| `sdk/` | Go, TypeScript, and Python consumer libraries |

## Reporting issues

- **Bugs and features:** [GitHub Issues](https://github.com/Abhishek-Parihar/authsvc/issues)
- **Security vulnerabilities:** see [SECURITY.md](SECURITY.md) — do not file public issues for security bugs.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
