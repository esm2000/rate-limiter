# Infrastructure & Operations

## Docker Compose Services

**`database`** — PostgreSQL. Mounts `database/init.sql` as the init script (runs only when the volume is empty). Named `database` volume for persistence. Port 5432. Healthcheck: `pg_isready`.

**`cache`** — Redis. Password auth (`--requirepass`), write-ahead persistence (`--save 20 1`). Named `cache` volume. Port 6379. Healthcheck: `redis-cli ping`.

**`test`** — Built from the same Dockerfile as `rate-limiter-core`. Runs `python3 -m pytest tests/integration/ -v`. Depends on `database` and `cache` being healthy. This is the integration test gate.

**`rate-limiter-core`** — Flask application. Depends on `test` completing successfully (`condition: service_completed_successfully`) plus `database` and `cache` being healthy. Port 3000. Mounts `./rate-limiter-core` for hot-reload.

## Multi-Stage Dockerfile

```
base        → installs requirements.txt, copies source
test        → FROM base, runs unit tests (python3 -m pytest tests/unit/ -v)
production  → FROM test, CMD ["python3", "app.py"]
```

If any unit test fails, the Docker build fails and no image is produced. This blocks both the `test` service and `rate-limiter-core` from starting. Integration tests run at `docker compose up` time (not build time) because they need live Redis/PostgreSQL.

## Environment Variables

Required in `.env` at repo root:

```
POSTGRES_USER=<username>
POSTGRES_PASSWORD=<password>
REDIS_PASSWORD=<password>
```

`POSTGRES_HOST` (default: `"database"`) and `REDIS_HOST` (default: `"cache"`) are correct for Docker Compose networking. Override to `localhost` for local test runs outside Docker.
