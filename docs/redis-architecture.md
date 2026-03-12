# Redis Architecture

## Key Naming Convention

All rate limiting state lives at a single key per user per rule:

```
{domain}:{category}:{identifier}:{user_id}
```

`domain` is the service UUID (e.g., `550e8400-e29b-41d4-a716-446655440000`). None of these fields may contain a colon — `validate_no_colon` is called at creation/use time. This guarantees that splitting on `:` is safe.

## Lock Key Convention

```
lock:{domain}:{category}:{identifier}:{user_id}
```

i.e., `lock:` prepended to the rate limiting key.

## Leaking Bucket Queue Key

`leaking_bucket_rule_queue` — a Redis LIST (not a hash). Items pushed with `LPUSH`, popped with `RPOP` (FIFO). Each item:

```
{domain}:{category}:{identifier}:{user_id}:{outflow_rate}
```

The worker reconstructs the Redis hash key from all segments except the last, and extracts the outflow rate from the last segment.

## Data Types

- **HASH** (`HSET`/`HGETALL`): All per-user algorithm state. Multiple fields need to be read and written as a unit.
- **LIST** (`LPUSH`/`RPOP`): `leaking_bucket_rule_queue`. FIFO queue semantics.
- **STRING** (`SET NX EX`): Distributed locks. `NX` is the atomic compare-and-set. `EX` is the auto-expiry deadlock safeguard.

## Distributed Lock Pattern

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
