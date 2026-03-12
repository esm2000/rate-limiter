# Leaking Bucket Background Worker

## Startup Sequence (`app.py`, `__main__` block)

1. Register `SIGINT`/`SIGTERM` to call `shutdown_leaking_bucket_processes()` (sets `_shutdown` event).
2. Call `refresh_leaking_bucket_queue()` — populate Redis work queue from PostgreSQL. Failure is caught and ignored.
3. Create and start a pool of `threading.Thread` instances targeting `manage_leaking_bucket_queues` (see `app.py` for the current count).
4. `app.run(debug=False, host="0.0.0.0", port=3000)` blocks.
5. On exit: call `shutdown_leaking_bucket_processes()`, join all threads.

## `manage_leaking_bucket_queues` Loop

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

## `refresh_leaking_bucket_queue`

Queries PostgreSQL for all leaking bucket rules, joining `rules` and `users` on `r.domain = u.service_id`:

```sql
SELECT r.domain, r.category, r.identifier, u.id AS user_id, r.rate_limit
FROM rules r JOIN users u ON r.domain = u.service_id
WHERE algorithm = 'leaking_bucket'
```

Clears `leaking_bucket_rule_queue` with `DELETE`, then pushes one entry per row: `{domain}:{category}:{identifier}:{user_id}:{rate_limit}`.

## Graceful Shutdown

`shutdown_leaking_bucket_processes()` sets `_shutdown`. Workers' `while not _shutdown.is_set()` loops exit naturally. Main thread calls `t.join()` on each.
