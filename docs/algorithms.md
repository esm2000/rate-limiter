# Rate Limiting Algorithms

Every algorithm reads and writes a Redis hash at `{domain}:{category}:{identifier}:{user_id}`. The decision (`check_if_request_is_allowed`) and increment (`increment_rate_limit_usage`) steps are separate, each protected by a distributed lock on `lock:{key}`.

## Algorithm Tradeoffs

| Algorithm              | Memory | Accuracy       | Burst Support        | Complexity |
|------------------------|--------|----------------|----------------------|------------|
| Token Bucket           | Low    | High           | Yes                  | Medium     |
| Leaking Bucket         | Medium | High (outflow) | No (smoothed)        | High       |
| Fixed Window Counter   | Low    | Medium         | Yes (boundary spike) | Low        |
| Sliding Window Log     | High   | Exact          | No                   | Medium     |
| Sliding Window Counter | Low    | ~99%           | No                   | Medium     |

---

## Token Bucket

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

---

## Leaking Bucket

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

---

## Fixed Window Counter

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

---

## Sliding Window Log

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

**Increment:** Append `current_time.isoformat()` to the timestamp string, rejoin with `|||`, write back. Sliding window log logs all attempts — allowed and denied — so the window reflects total request pressure, not just approved requests.

---

## Sliding Window Counter

**Concept:** Maintains a request count for the current fixed-width window and the previous window. Uses a linear overlap calculation to estimate requests within the rolling window at the current moment:

```
rolling_count = current_window_count + previous_window_count * overlap_ratio
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
