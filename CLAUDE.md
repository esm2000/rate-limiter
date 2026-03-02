# rate-limiter

A distributed, low-latency rate limiter implemented as a standalone middleware service. Implements five classic rate-limiting algorithms from Alex Xu's *System Design Interview* (Vol. 1, Chapter 4) backed by Redis for shared state and PostgreSQL for rule persistence. Portfolio project demonstrating system design thinking, distributed systems patterns, and AI-assisted engineering workflows.

---

## Workflow Instructions for Claude

**Keep this file current.** When a task changes the project — new route, schema change, new algorithm, new service, changed convention, renamed field — update the relevant section of this file in the same commit. CLAUDE.md is the source of truth for future sessions; a stale CLAUDE.md is worse than none.

**Always enter plan mode before implementing anything non-trivial.** Non-trivial means: touching more than one file, changing data flow between services, adding a new route, modifying the database schema, or anything architectural. Read relevant files before making assumptions.

**Commit style:** One sentence, imperative mood, no co-author line. Example: `Add sliding window counter unit tests`.

**Always push to main after committing** unless told otherwise.

**Design infrastructure before implementing.** If a task needs a new Docker service, env var, or schema migration, plan that first.

**Read files before editing.** Never suggest changes to code you haven't read in the current session.

**No over-engineering.** No docstrings, type annotations, or error handling for scenarios that cannot happen. No helpers or abstractions for one-time use. No backwards-compatibility shims.

**Run tests before committing.** Unit tests: `python3 -m pytest rate-limiter-core/tests/unit/ -v`.

**Validation ordering matters.** Always: auth header present → service/user exists → API token valid → business rules. Existing code follows this consistently.

**Field names are load-bearing.** Redis hash field names (`fw_num_requests`, `swc_time_window_start`, `last_token_count`, `queue`, `timestamps`) are read and written by separate functions. Renaming breaks the read/write contract.

---

## System Design Context

### Why a Rate Limiter?

APIs without rate limiting are vulnerable to abuse: denial-of-service attacks, credential stuffing, runaway client bugs, and uneven resource consumption. A rate limiter enforces maximum request throughput per user per rule, returning HTTP 429 when the limit is exceeded. Beyond security, it enables fair multi-tenancy — one service's traffic spike cannot starve another.

### Placement Decision

Alex Xu surveys three placements: client-side (bypassable), server-side middleware (coupled to application code), and dedicated middleware service (fully decoupled). This project implements the **dedicated middleware approach**. Clients send requests to `/redirect` with a target URL. The rate limiter checks Redis state, allows or denies, and forwards allowed requests to the upstream using the `requests` library. Rate limiting logic is entirely decoupled from any upstream service.

### Design Goals

- **Low latency**: Rate limiting decision is a Redis hash read + optional write. No database queries on the hot path once a rule is loaded.
- **Distributed**: Redis is shared state. Multiple rate-limiter-core instances can run behind a load balancer sharing the same counters.
- **Fault tolerance**: Distributed locks (`SET NX EX`) prevent race conditions. Lock acquisition failures cause denial rather than double-counting.
- **Flexible rules**: Rules are stored in PostgreSQL. Any service can register rules with any algorithm, window size, and rate limit via the API.

### Rate Limit Exceeded Behavior

HTTP 429 with body `{"error": "Rate limit exceeded"}`. No `Retry-After` header.

### Algorithm Tradeoffs

| Algorithm              | Memory | Accuracy       | Burst Support        | Complexity |
|------------------------|--------|----------------|----------------------|------------|
| Token Bucket           | Low    | High           | Yes                  | Medium     |
| Leaking Bucket         | Medium | High (outflow) | No (smoothed)        | High       |
| Fixed Window Counter   | Low    | Medium         | Yes (boundary spike) | Low        |
| Sliding Window Log     | High   | Exact          | No                   | Medium     |
| Sliding Window Counter | Low    | ~99%           | No                   | Medium     |

---

## Repository Structure

```
rate-limiter/
├── CLAUDE.md                        # This file — Claude's persistent project context
├── README.md                        # Human-facing getting-started guide
├── Makefile                         # (empty placeholder)
├── docker-compose.yml               # Orchestrates all services
├── database/
│   └── init.sql                     # PostgreSQL schema — runs once on first volume creation
├── rate-limiter-core/               # Flask application — the rate limiter service
│   ├── Dockerfile                   # Multi-stage: base → test (unit) → production
│   ├── requirements.txt             # Python dependencies
│   ├── app.py                       # Flask app, all routes, startup/shutdown
│   ├── throttle.py                  # All 5 algorithms + leaking bucket worker
│   ├── cache.py                     # Redis wrapper (all cache operations)
│   ├── db.py                        # PostgreSQL wrapper (get_data, alter)
│   ├── rule.py                      # Rule CRUD business logic
│   ├── service.py                   # Service CRUD business logic
│   ├── user.py                      # User CRUD business logic
│   ├── util.py                      # Shared validation helpers + shared queries
│   ├── hash.py                      # bcrypt hash and verify helpers
│   └── tests/
│       ├── unit/
│       │   ├── conftest.py          # mock_db (psycopg2.connect), mock_cache (cache.cache)
│       │   ├── test_hash.py
│       │   ├── test_rule.py
│       │   ├── test_service.py
│       │   ├── test_throttle.py
│       │   ├── test_user.py
│       │   └── test_util.py
│       └── integration/
│           ├── conftest.py          # redis_client, pg_dsn, flask_client, clean_redis
│           ├── test_app.py          # End-to-end route tests (stubs — pass immediately)
│           ├── test_cache.py        # Redis operation tests
│           ├── test_db.py           # PostgreSQL operation tests
│           └── test_throttle.py     # Algorithm tests against real Redis
└── rule-worker/                     # Placeholder — future rule worker service
```

---

## Infrastructure & Operations

### Docker Compose Services

**`database`** — PostgreSQL. Mounts `database/init.sql` as the init script (runs only when the volume is empty). Named `database` volume for persistence. Port 5432. Healthcheck: `pg_isready`.

**`cache`** — Redis. Password auth (`--requirepass`), write-ahead persistence (`--save 20 1`). Named `cache` volume. Port 6379. Healthcheck: `redis-cli ping`.

**`test`** — Built from the same Dockerfile as `rate-limiter-core`. Runs `python3 -m pytest tests/integration/ -v`. Depends on `database` and `cache` being healthy. This is the integration test gate.

**`rate-limiter-core`** — Flask application. Depends on `test` completing successfully (`condition: service_completed_successfully`) plus `database` and `cache` being healthy. Port 3000. Mounts `./rate-limiter-core` for hot-reload.

### Multi-Stage Dockerfile

```
base        → installs requirements.txt, copies source
test        → FROM base, runs unit tests (python3 -m pytest tests/unit/ -v)
production  → FROM test, CMD ["python3", "app.py"]
```

If any unit test fails, the Docker build fails and no image is produced. This blocks both the `test` service and `rate-limiter-core` from starting. Integration tests run at `docker compose up` time (not build time) because they need live Redis/PostgreSQL.

### Environment Variables

Required in `.env` at repo root:

```
POSTGRES_USER=<username>
POSTGRES_PASSWORD=<password>
REDIS_PASSWORD=<password>
```

`POSTGRES_HOST` (default: `"database"`) and `REDIS_HOST` (default: `"cache"`) are correct for Docker Compose networking. Override to `localhost` for local test runs outside Docker.

### How to Run

**First time or after schema changes (`init.sql` modified):**
```bash
docker compose down -v && docker compose up --build
```
`-v` destroys named volumes. PostgreSQL's init script only runs when the data directory is empty.

**Subsequent runs:**
```bash
docker compose up --build
```
Always use `--build` when Python source files changed. Without it, Docker may use a cached image.

**Unit tests only:**
```bash
python3 -m pytest rate-limiter-core/tests/unit/ -v
```

---

## Database Schema

Defined in `database/init.sql`. Table creation order follows FK dependencies: `services` before `users`, `services` before `rules`.

### `services`

```sql
CREATE TABLE services (
    id                      UUID PRIMARY KEY,
    name                    VARCHAR,
    creation_time           TIMESTAMP,
    api_key_expiration_time TIMESTAMP,
    api_key_hash            VARCHAR
);
```

`id` is UUID v4 from `uuid.uuid4()`. `name` must be unique and may not contain colons. `api_key_hash` is bcrypt — the plaintext key is returned once at creation and never stored. `api_key_expiration_time` is 7 days from creation or last rotation.

### `users`

```sql
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    service_id    UUID,
    is_admin      BOOLEAN,
    creation_time TIMESTAMP,
    password_hash VARCHAR,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
```

`ON DELETE CASCADE` — deleting a service deletes all its users. Every service has at least one admin (created atomically with the service). The last admin cannot be deleted.

### `rules`

```sql
CREATE TABLE rules (
    domain      UUID,
    category    VARCHAR,
    identifier  VARCHAR,
    PRIMARY KEY (domain, category, identifier),
    rate_limit  INTEGER,
    window_size BIGINT,
    algorithm   VARCHAR,
    FOREIGN KEY (domain) REFERENCES services(id) ON DELETE CASCADE
);
```

**`domain` is a UUID, not a VARCHAR service name.** An earlier version used VARCHAR here, which broke foreign key enforcement. The fix was changing it to UUID and adding the FK constraint. When creating a rule, pass `service_id` (the UUID), not `service_name`. `ON DELETE CASCADE` deletes all rules when a service is deleted.

`(domain, category, identifier)` is the composite primary key — a service can have many rules as long as each `(category, identifier)` pair is unique within that service. `algorithm` must be one of the five valid strings.

---

## API Reference

Base URL: `http://localhost:3000`. Auth uses `Authorization: Bearer <api_key>` where `api_key` is the plaintext value returned at service creation or token rotation.

### `GET /`
Health check. No auth. Returns `200 rate-limiter-core`.

---

### `POST /service`
Create a service. No auth. Body: `{"service_name": "...", "admin_password": "..."}`.

`service_name` must be unique and contain no colons. Returns `201` with `service_id`, `api_key`, `admin_user_id`. Save `api_key` — returned only once, valid 7 days.

---

### `GET /service/<service_id>`
Get service info. Bearer token required. Returns `200` with `service_name`, `creation_time`, `api_key_expiration_time`.

### `PUT /service/<service_id>`
Rename service. Bearer token required. Body: `{"new_service_name": "..."}`. New name cannot match current name, cannot contain colons. Returns `200`.

### `DELETE /service/<service_id>`
Delete service (cascades to users and rules). Bearer token required. Returns `200`.

---

### `POST /service/<service_id>/token/rotate`
Rotate API key. No bearer token — authenticated by admin credentials. Body: `{"user_id": "...", "password": "..."}`. User must be admin of the service. Returns `200` with new `token`. Old key is immediately invalidated; new key expires in 7 days.

---

### `POST /user`
Create user. Bearer token required. Body: `{"service_id": "...", "password": "...", "is_admin": false}`. `is_admin` defaults to `false`. Returns `201` with `user_id`.

### `GET /user/<user_id>`
Get user info. Bearer token (admin) OR user's own credentials. Body: `{"service_id": "...", "password": "..."}`. Returns `200` with `service_id`, `is_admin`, `creation_time`.

### `PUT /user/<user_id>`
Update password. Bearer token (admin) OR user's own credentials. Body: `{"service_id": "...", "password": "...", "new_password": "..."}`. New password cannot match current. Returns `200`.

### `DELETE /user/<user_id>`
Delete user. Bearer token required. Cannot delete last admin user (`403`). Returns `200`.

---

### `POST /rule`
Create rule. Bearer token required.

Body:
```json
{
  "domain": "<service_id UUID>",
  "category": "messaging",
  "identifier": "send_message",
  "window_size": 60,
  "rate_limit": 100,
  "algorithm": "fixed_window"
}
```

`domain`, `category`, `identifier` cannot contain colons. `(domain, category, identifier)` must be unique. `window_size` and `rate_limit` must be positive. `algorithm` must be one of the five valid values. Returns `201`.

### `GET /rule`
Get rule config. Bearer token required. Body: `{"domain": "...", "category": "...", "identifier": "..."}`. Returns `200` with `window_size`, `rate_limit`, `algorithm`.

### `PUT /rule`
Update rule. Bearer token required. Same body shape as GET, plus new values for any of `window_size`, `rate_limit`, `algorithm`. At least one field must change. Returns `200`.

### `DELETE /rule`
Delete rule. Bearer token required. Body: `{"domain": "...", "category": "...", "identifier": "..."}`. Returns `200`.

---

### `POST /redirect`
The core rate-limiting endpoint. Checks the rule, forwards allowed requests to the upstream.

Body:
```json
{
  "domain": "<service_id UUID>",
  "category": "messaging",
  "identifier": "send_message",
  "user_id": "<user UUID>",
  "password": "userpassword",
  "redirect_url": "https://api.example.com/messages",
  "redirect_method": "POST",
  "redirect_params": {},
  "redirect_args": {"content": "hello"}
}
```

`redirect_method` is case-insensitive; must be GET, OPTIONS, HEAD, POST, PUT, PATCH, or DELETE. `redirect_params` and `redirect_args` must be dicts (or omitted).

**Response 200** (non-leaking-bucket, allowed): `{"status": <upstream_status>, "response": "<upstream_body>"}`.

**Response 200** (leaking bucket, queued): `{"status": 202}`. The `/redirect` call itself returns 200; the `202` in the body means the request was accepted for async processing.

**Response 429**: `{"error": "Rate limit exceeded"}`.

**Response 400**: Invalid `redirect_method`, non-dict `redirect_args`/`redirect_params`, or validation error.

**Response 401**: Invalid user credentials.

**Response 502**: Upstream request failed.

---

## Rate Limiting Algorithms

Every algorithm reads and writes a Redis hash at `{domain}:{category}:{identifier}:{user_id}`. The decision (`check_if_request_is_allowed`) and increment (`increment_rate_limit_usage`) steps are separate, each protected by a distributed lock on `lock:{key}`.

---

### Token Bucket

**Concept:** A virtual bucket holds up to `window_size` tokens. One token is added every `rate_limit` seconds. A request is allowed if at least one token is available; one token is consumed on the increment step. Burst traffic up to `window_size` is absorbed; sustained traffic is rate-limited to one request per `rate_limit` seconds.

**Parameters:** `window_size` = bucket capacity. `rate_limit` = refill interval in seconds.

**Redis hash fields:**
- `last_request_time`: ISO 8601 UTC string. Absent → synthetic time that fully refills bucket (`current_time - (bucket_size * refill_rate + 1)` seconds ago).
- `last_token_count`: String-encoded integer.

**TTL:** `rate_limit + 60` seconds.

**Decision flow:**
1. Compute `seconds_since_last_request = (current_time - last_request_time).total_seconds()`.
2. `tokens_to_add = int(seconds_since_last_request / rate_limit)`.
3. `current_token_count = min(last_token_count + tokens_to_add, window_size)`.
4. Allow if `current_token_count > 0`. Write `last_request_time = current_time.isoformat()` and `last_token_count = str(current_token_count)`.

**Increment:** Decrement `last_token_count` by 1. Update `last_request_time` to `current_time.isoformat()`.

**Alex Xu:** Easy to implement, memory-efficient, handles bursts. Tricky to tune two parameters. Token bucket and leaking bucket are from the same algorithmic family but differ in whether traffic is smoothed on input (leaking) or on output (token).

---

### Leaking Bucket

**Concept:** Each user/rule has a FIFO queue. Requests are accepted (queued) if the queue is below capacity (`window_size`). A background worker drains the queue at one request per `rate_limit` seconds, making the actual upstream call. This smooths bursty input into a constant outflow rate.

**Parameters:** `window_size` = maximum queue depth. `rate_limit` = outflow interval in seconds (one request drained per `rate_limit` seconds).

**Redis hash fields:**
- `queue`: JSON-encoded array of request objects. Each object has keys `url`, `method`, `params`, `args`.
- `last_outflow_time`: ISO 8601 datetime of the last worker drain. Used by the worker to time the next drain.

**Redis list key:** `leaking_bucket_rule_queue` — a LIST cycled by the worker. Entries: `{domain}:{category}:{identifier}:{user_id}:{outflow_rate}`.

**TTL (increment step):** `rate_limit + 60` seconds. **TTL (worker step):** `outflow_rate * max(remaining_queue_length, 1) + 30` — long enough to drain the remaining queue.

**Decision flow:**
1. Parse `queue` from JSON (default `"[]"`).
2. Allow if `len(queue) < window_size`.

**Increment:** Append `{"url": ..., "method": ..., "params": ..., "args": ...}` to the queue JSON, write back.

**Alex Xu:** Stable outflow protects downstream. Queue depth determines latency for enqueued requests. No burst delivery upstream.

---

### Fixed Window Counter

**Concept:** Time is divided into fixed `window_size`-second epochs. Each epoch has a counter. A request is allowed if the counter is below `rate_limit`; the counter increments on the increment step. When the epoch expires, the counter resets to 0.

**Parameters:** `window_size` = epoch duration in seconds. `rate_limit` = max requests per epoch.

**Redis hash fields:**
- `fw_time_window_start`: ISO 8601 UTC string. Start of the active window. Absent → set to `current_time`.
- `fw_num_requests`: String-encoded integer. Resets to 0 when the window advances.

**TTL:** `window_size + 60` seconds.

**Decision flow:**
1. If `fw_time_window_start` absent, set to `current_time`, `fw_num_requests` to 0.
2. While `time_window_start + window_size < current_time`, advance by `window_size`, reset `num_requests = 0`.
3. Allow if `num_requests < rate_limit`. Write updated `fw_time_window_start` and `fw_num_requests`.

**Increment:** Increment `fw_num_requests` by 1.

**Alex Xu:** Simplest algorithm. Vulnerable to boundary spikes — a client can send `rate_limit` requests in the last second of a window and `rate_limit` more in the first second of the next window, doubling the effective rate in a short burst. Fixed window counter is the canonical motivating example for sliding window algorithms.

---

### Sliding Window Log

**Concept:** Every request timestamp (allowed and denied) is logged. On each request, the algorithm removes timestamps older than `window_size` seconds, counts the remainder, and allows if the count is below `rate_limit`. No epoch boundaries — the window slides continuously.

**Parameters:** `window_size` = rolling window duration in seconds. `rate_limit` = max requests in any `window_size`-second span.

**Redis hash fields:**
- `timestamps`: A `|||`-separated string of ISO 8601 UTC datetime strings. Empty string = no prior requests.

The `|||` separator is chosen because it cannot appear in an ISO 8601 datetime string, making unambiguous splitting possible.

**TTL:** `window_size + 60` seconds.

**Decision flow:**
1. Split `timestamps` on `|||` (empty string → `[]`).
2. `window_start = current_time - timedelta(seconds=window_size)`.
3. Keep only timestamps where `datetime.fromisoformat(ts) >= window_start`.
4. Allow if `len(trimmed_timestamps) + 1 <= rate_limit`. Write `"|||".join(trimmed_timestamps)`.

**Increment:** Append `current_time.isoformat()` to the timestamp string, rejoin with `|||`, write back. **Sliding window log logs all attempts — allowed and denied** — so the window reflects total request pressure, not just approved requests. This prevents a client from flooding denied requests to game the counter.

**Alex Xu:** Most accurate algorithm. Memory cost is proportional to traffic volume × window size — can be large for high-traffic rules. The logging-of-denials design choice is deliberate.

---

### Sliding Window Counter

**Concept:** Maintains a request count for the current fixed-width window and the previous window. Uses a linear overlap calculation to estimate requests within the rolling window at the current moment:

```
rolling_count = current_window_count + previous_window_count × overlap_ratio
overlap_ratio = 1 - (seconds_since_window_start / window_size)
```

This approximation is typically within ~1% of the true rate.

**Parameters:** `window_size` = epoch duration in seconds. `rate_limit` = max estimated requests in rolling window.

**Redis hash fields:**
- `swc_time_window_start`: ISO 8601 string — pointer to the current window's start.
- Dynamic ISO datetime keys: String-encoded request counts per window epoch. The current epoch key plus up to 3 previous epoch keys are retained (for soft redundancy during purge).

**TTL:** `window_size + 60` seconds.

**Decision flow:**
1. Read `swc_time_window_start` (default `current_time`). Advance forward by `window_size` until the window contains `current_time`.
2. `previous_time_window_start = time_window_start - timedelta(seconds=window_size)`.
3. Look up `current_num_requests = log[time_window_start_str]` and `previous_num_requests = log[previous_time_window_start_str]`, both default 0.
4. `overlap_ratio = 1 - ((current_time - time_window_start).total_seconds() / window_size)`.
5. `rolling_count = floor(current_num_requests + previous_num_requests * overlap_ratio)`.
6. Allow if `rolling_count < rate_limit`. Write `swc_time_window_start`.

**Increment:** Increment `log[swc_time_window_start]` by 1. Purge all window keys more than 3 epochs old (retain `swc_time_window_start`, current epoch, and the three prior epochs).

**Alex Xu:** Approximation is ~99% accurate. Far more memory-efficient than sliding window log for high-traffic rules. Does not capture exact traffic at window boundaries.

---

## Redis Architecture

### Key Naming Convention

All rate limiting state lives at a single key per user per rule:

```
{domain}:{category}:{identifier}:{user_id}
```

`domain` is the service UUID (e.g., `550e8400-e29b-41d4-a716-446655440000`). None of these fields may contain a colon — `validate_no_colon` is called at creation/use time. This guarantees that splitting on `:` is safe.

### Lock Key Convention

```
lock:{domain}:{category}:{identifier}:{user_id}
```

i.e., `lock:` prepended to the rate limiting key.

### Leaking Bucket Queue Key

`leaking_bucket_rule_queue` — a Redis LIST (not a hash). Items pushed with `LPUSH`, popped with `RPOP` (FIFO). Each item:

```
{domain}:{category}:{identifier}:{user_id}:{outflow_rate}
```

The worker reconstructs the Redis hash key from all segments except the last, and extracts the outflow rate from the last segment.

### Data Types

- **HASH** (`HSET`/`HGETALL`): All per-user algorithm state. Multiple fields need to be read and written as a unit.
- **LIST** (`LPUSH`/`RPOP`): `leaking_bucket_rule_queue`. FIFO queue semantics.
- **STRING** (`SET NX EX`): Distributed locks. `NX` is the atomic compare-and-set. `EX` is the auto-expiry deadlock safeguard.

### Distributed Lock Pattern

```python
if not acquire_lock(lock_key, timeout=2):
    return False, is_leaking_bucket   # deny rather than risk double-count

try:
    # read → decide → update → store
    ...
finally:
    release_lock(lock_key)   # always release, even on exception
```

`acquire_lock` is `cache.set(lock_key, "1", nx=True, ex=timeout)` — returns truthy if set (lock acquired), falsy if already exists (held). `try/finally` guarantees release. Lock timeout: 2 seconds for the decision step, 5 seconds for the increment step.

---

## Authentication & Authorization

### Bearer Token (API Key)

Generated with `secrets.token_urlsafe(32)` — 32 bytes of cryptographic randomness, base64url-encoded (~43 chars). Plaintext returned once (creation or rotation), never stored. Only the bcrypt hash persists in `services.api_key_hash`. Valid for 7 days.

**Validation (`validate_api_token` in `util.py`):**
1. Extract key from `Authorization: Bearer <key>`.
2. Fetch `api_key_hash` from PostgreSQL.
3. `verify(key, api_key_hash)` (bcrypt `checkpw`). Raise 401 if mismatch.
4. Check `api_key_expiration_time`. Raise 401 if expired.

### User Credentials

Users authenticate with `user_id` (UUID) + `password` (plaintext). Password hash stored with bcrypt. Validation via `validate_user_id_and_password`.

### Per-Route Authorization Matrix

| Endpoint | Bearer Token | User Credentials | Notes |
|----------|-------------|-----------------|-------|
| `POST /service` | — | — | No auth |
| `GET/PUT/DELETE /service/<id>` | Required | — | Service's API key |
| `POST /service/<id>/token/rotate` | — | Required | Admin user only |
| `POST /user` | Required | — | Service's API key |
| `GET/PUT /user/<id>` | Optional | Optional | Either admin token OR own credentials |
| `DELETE /user/<id>` | Required | — | Admin; cannot delete last admin |
| `POST/GET/PUT/DELETE /rule` | Required | — | Service's API key |
| `POST /redirect` | — | Required | User's own credentials |

### Validation Ordering

All protected routes:
1. Auth header present and well-formed (`validate_auth_header_present_and_not_malformed`)
2. Service exists (`validate_service_exists`)
3. API token valid (`validate_api_token`)
4. Business rules

---

## Leaking Bucket Background Worker

### Startup Sequence (`app.py`, `__main__` block)

1. Register `SIGINT`/`SIGTERM` to call `shutdown_leaking_bucket_processes()` (sets `_shutdown` event).
2. Call `refresh_leaking_bucket_queue()` — populate Redis work queue from PostgreSQL. Failure is caught and ignored.
3. Create and start a pool of `threading.Thread` instances targeting `manage_leaking_bucket_queues` (see `app.py` for the current count).
4. `app.run(debug=False, host="0.0.0.0", port=3000)` blocks.
5. On exit: call `shutdown_leaking_bucket_processes()`, join all threads.

### `manage_leaking_bucket_queues` Loop

Each worker thread loops until `_shutdown` is set:

1. **Refresh check:** Attempt to acquire `lock:leaking_bucket_refresh`. If acquired, check if 30+ seconds have passed since `_last_refresh`. If so, call `refresh_leaking_bucket_queue()` and update `_last_refresh`. Release lock. The distributed lock ensures only one worker thread refreshes at a time.

2. **Pop rule:** `RPOP leaking_bucket_rule_queue`. If empty, `sleep(1)` and continue.

3. **Parse entry:** Split on `:`. Last segment = `outflow_rate`. Remaining segments joined = Redis hash key.

4. **Lock rule:** Acquire `lock:{redis_key}`. If failed, push entry back to queue, `sleep(1)`, continue.

5. **Drain logic:** Read hash. Compute `last_outflow_time` (default: `now - outflow_rate` seconds for immediate first drain). If `(current_time - last_outflow_time).total_seconds() >= outflow_rate`, pop queue[0], call upstream, remove from queue, update `last_outflow_time`.

6. **Retry:** Upstream call wrapped with tenacity `@retry` — exponential backoff, capped attempts. See `throttle.py` for current parameters.

7. **Store:** Write hash back. TTL = `outflow_rate * max(len(remaining_queue), 1) + 30`.

8. **Push back:** Return entry to `leaking_bucket_rule_queue` for next cycle.

9. `sleep(1)`.

### `refresh_leaking_bucket_queue`

Queries PostgreSQL for all leaking bucket rules, joining `rules` and `users` on `r.domain = u.service_id`:

```sql
SELECT r.domain, r.category, r.identifier, u.id AS user_id, r.rate_limit
FROM rules r JOIN users u ON r.domain = u.service_id
WHERE algorithm = 'leaking_bucket'
```

Clears `leaking_bucket_rule_queue` with `DELETE`, then pushes one entry per row: `{domain}:{category}:{identifier}:{user_id}:{rate_limit}`.

### Graceful Shutdown

`shutdown_leaking_bucket_processes()` sets `_shutdown`. Workers' `while not _shutdown.is_set()` loops exit naturally. Main thread calls `t.join()` on each.

---

## Code Module Responsibilities

**`app.py`** — Flask app factory, all route handlers, `UTCJSONProvider` class, leaking bucket startup/shutdown sequence. Imports from every other module. `UTCJSONProvider` formats all `datetime` objects as `"YYYY-MM-DD HH:MM:SS UTC"`.

**`throttle.py`** — All five algorithm implementations. Two public entry points: `check_if_request_is_allowed` and `increment_rate_limit_usage`. Per-algorithm helpers for each of the five algorithms. Leaking bucket background worker: `manage_leaking_bucket_queues`, `refresh_leaking_bucket_queue`, `shutdown_leaking_bucket_processes`. Largest and most complex module.

**`cache.py`** — Thin Redis wrapper. Module-level `cache` client. Exports: `retrieve_hash`, `store_hash`, `retrieve_value`, `store_value`, `increment_value`, `decrement_value`, `push_to_list`, `pop_from_list`, `clear_list`, `acquire_lock`, `release_lock`. No business logic.

**`db.py`** — Thin PostgreSQL wrapper. Builds DSN from env vars. Exports: `get_data_from_database(query, params)` → `fetchall()`, `alter_database(query, params)`. Opens a new connection per call.

**`rule.py`** — Rule CRUD. Validates auth, service existence, no-colon constraints, rate limit positivity, algorithm validity, and `(domain, category, identifier)` uniqueness before writing. Exports: `create_rule`, `get_rule_info`, `update_rule`, `delete_rule`.

**`service.py`** — Service CRUD and token rotation. Generates UUIDs, API keys (`secrets.token_urlsafe(32)`), bcrypt hashes at creation. Exports: `create_service`, `get_service_info`, `update_service`, `delete_service`, `renew_api_token`.

**`user.py`** — User CRUD. Validates auth (Bearer or user credentials), enforces last-admin constraint on delete. Exports: `create_user`, `get_user_info`, `update_user`, `delete_user`.

**`util.py`** — Shared validation helpers and shared queries used by multiple modules. Key exports: `validate_no_colon`, `validate_api_token`, `validate_service_exists`, `validate_auth_header_present_and_not_malformed`, `validate_auth_for_service`, `validate_auth_or_password`, `validate_category_identifier_combination`, `validate_rate_limit`, `validate_algorithm`, `get_rule_from_database`, `get_all_leaking_bucket_rule_info`, `is_valid_uuid`.

**`hash.py`** — Two functions: `hash(password)` → bcrypt hash string, `verify(password, hashed_password)` → bool.

---

## Testing Strategy

### Unit Tests (`tests/unit/`)

100% mocked — no live Redis or PostgreSQL required. Tests logic in isolation.

**`conftest.py` fixtures:**
- `mock_db`: Patches `psycopg2.connect` with `MagicMock`. Yields `(mock_connect, mock_conn, mock_cur)`.
- `mock_cache`: Patches `cache.cache` (the module-level Redis client in `cache.py`) with `MagicMock`.
- `is_valid_uuid(uuid_string)`: Helper for asserting UUID format.

**Run:**
```bash
python3 -m pytest rate-limiter-core/tests/unit/ -v
```

These also run at Docker image build time (the `test` stage). Failing unit test = failed build = no image = neither the `test` nor `rate-limiter-core` service starts.

**Test files:** `test_hash.py`, `test_rule.py`, `test_service.py`, `test_throttle.py`, `test_user.py`, `test_util.py`.

### Integration Tests (`tests/integration/`)

Run against real Redis and PostgreSQL from Docker Compose.

**`conftest.py` fixtures:**
- `redis_client` (session scope): Real Redis connection using env vars. Calls `flushall()` at session teardown.
- `clean_redis`: Yields, then calls `redis_client.flushall()`. Use on any test that writes to Redis.
- `pg_dsn` (session scope): Returns PostgreSQL connection string for direct psycopg2 use.
- `flask_client`: Flask test client with `TESTING=True`.

**Run:** `docker compose up --build`. The `test` service runs integration tests; `rate-limiter-core` only starts when `test` exits successfully.

**Test files:**
- `test_app.py`: End-to-end HTTP tests — full service/user/rule lifecycle, all five algorithms at `/redirect`, redirect input validation.
- `test_cache.py`: Redis wrapper operations.
- `test_db.py`: PostgreSQL wrapper operations.
- `test_throttle.py`: Algorithm behavior against real Redis.

---

## Conventions & Patterns

### Error Handling

Werkzeug HTTP exceptions (`BadRequest`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `InternalServerError`) for all expected error conditions. Route handlers catch `InternalServerError` → 500 JSON. Other Werkzeug exceptions propagate to Flask's default error handler. Business logic raises exceptions directly — no error codes returned.

### State Management Pattern

All algorithm functions: read → decide → update → store:

1. Read current state from Redis hash (with defaults for missing keys).
2. Decide whether request is allowed.
3. Update in-memory state (without consuming the resource yet).
4. Write updated state to Redis.
5. Release lock.
6. (After upstream request succeeds) acquire lock, consume resource, write, release.

This two-phase approach (decide, then commit) ensures the upstream is only called for allowed requests, and the counter is only decremented when the call succeeds.

### Datetime Handling

All datetimes are UTC. `datetime.now(timezone.utc)` for current time. `.isoformat()` for Redis serialization. `UTCJSONProvider` in `app.py` ensures all `datetime` objects in JSON responses format as `"YYYY-MM-DD HH:MM:SS UTC"`.

### Field Name Prefixes

Hash fields are prefixed to prevent collision:
- `fw_` prefix: fixed window (`fw_time_window_start`, `fw_num_requests`)
- `swc_` prefix: sliding window counter (`swc_time_window_start`)
- Unprefixed: token bucket (`last_request_time`, `last_token_count`), leaking bucket (`queue`, `last_outflow_time`), sliding window log (`timestamps`)

### Timestamp Separator

Sliding window log uses `|||` to separate timestamps in the `timestamps` hash field. ISO 8601 datetime strings never contain `|`, so splitting on `|||` is unambiguous without JSON parse overhead.

### No Colon in Identifiers

`domain`, `category`, `identifier`, `service_name`, and `user_id` all pass through `validate_no_colon` before persisting. Redis key reconstruction depends on splitting on `:` with a known structure — a colon in any of these values would corrupt the key and break all algorithm operations for that rule.
