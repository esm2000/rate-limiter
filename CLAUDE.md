# rate-limiter

Distributed rate limiter middleware service. Five algorithms (token bucket, leaking bucket, fixed window counter, sliding window log, sliding window counter) from Alex Xu's *System Design Interview* Ch. 4. Redis for shared state, PostgreSQL for rule persistence. Flask API on port 3000.

Clients hit `POST /redirect` with a target URL. The service checks rate limits against Redis, returns 429 or forwards the request upstream.

## Workflow

- **Plan first.** Enter plan mode before touching >1 file, changing data flow, adding routes, or modifying schema.
- **Read before editing.** Never modify code you haven't read this session.
- **Commit style.** One sentence, imperative mood, no co-author line. Example: `Add sliding window counter unit tests`.
- **Push to main after committing** unless told otherwise.
- **Run unit tests before committing:** `python3 -m pytest rate-limiter-core/tests/unit/ -v`
- **No over-engineering.** No docstrings, type annotations, or error handling for impossible scenarios. No helpers for one-time use.
- **Keep CLAUDE.md and `docs/` current.** When a task changes the project, update the relevant section of this file or the corresponding doc in the same commit.

## Commands

```bash
# Unit tests (also run at Docker build time — failure blocks the image)
python3 -m pytest rate-limiter-core/tests/unit/ -v

# Full stack (integration tests gate the app — app only starts if tests pass)
docker compose up --build

# Integration tests only (exits when tests finish)
docker compose up --build --abort-on-container-exit --exit-code-from test

# After schema changes (init.sql) — must destroy volumes first
docker compose down -v && docker compose up --build
```

Always use `--build` when Python source changed. `.env` at repo root needs `POSTGRES_USER`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`.

## Critical Invariants

These cause silent data corruption or broken functionality if violated:

- **No colons in identifiers.** `domain`, `category`, `identifier`, `service_name` pass through `validate_no_colon`. Redis keys are split on `:` — a colon in any value corrupts the key.
- **`rules.domain` is a UUID, not a service name.** FK references `services(id)`. Pass `service_id`, not `service_name`.
- **Redis field names are load-bearing.** `fw_num_requests`, `swc_time_window_start`, `last_token_count`, `queue`, `timestamps` — read and written by separate functions. Renaming breaks the contract.
- **Validation ordering.** Always: auth header present → service exists → API token valid → business rules.
- **Sliding window log `|||` separator.** The `timestamps` field uses `|||` between ISO 8601 strings. Cannot be changed without breaking parsing.

## Module Map

All source is in `rate-limiter-core/`:

| File | Responsibility |
|------|---------------|
| `app.py` | Flask routes, `UTCJSONProvider`, leaking bucket worker startup/shutdown |
| `throttle.py` | All 5 algorithms (`check_if_request_is_allowed`, `increment_rate_limit_usage`), leaking bucket worker |
| `cache.py` | Thin Redis wrapper — hash/list/lock operations, module-level `cache` client |
| `db.py` | Thin PostgreSQL wrapper — `get_data_from_database`, `alter_database` |
| `rule.py` | Rule CRUD with validation |
| `service.py` | Service CRUD, UUID/API key generation, token rotation |
| `user.py` | User CRUD, last-admin constraint |
| `util.py` | Shared validators and queries used across modules |
| `hash.py` | bcrypt `hash` and `verify` |

Tests: `tests/unit/` (fully mocked, `conftest.py` provides `mock_db` and `mock_cache`) and `tests/integration/` (real Redis/PostgreSQL via Docker Compose).

## Detailed Reference

Read these docs only when working on the relevant area:

- `docs/algorithms.md` — Redis field names, decision flows, TTLs, and parameter semantics for all 5 algorithms
- `docs/api-reference.md` — Every endpoint: method, auth, request/response shape, status codes
- `docs/database-schema.md` — Table definitions, FK relationships, cascade behavior
- `docs/redis-architecture.md` — Key naming, lock patterns, data types, distributed lock protocol
- `docs/auth.md` — Bearer token lifecycle, user credentials, per-route authorization matrix
- `docs/leaking-bucket-worker.md` — Background worker startup, drain loop, refresh cycle, shutdown
- `docs/infrastructure.md` — Docker Compose services, multi-stage Dockerfile, environment variables
