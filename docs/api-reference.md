# API Reference

Base URL: `http://localhost:3000`. Auth uses `Authorization: Bearer <api_key>` where `api_key` is the plaintext value returned at service creation or token rotation.

## `GET /`
Health check. No auth. Returns `200 rate-limiter-core`.

---

## `POST /service`
Create a service. No auth. Body: `{"service_name": "...", "admin_password": "..."}`.

`service_name` must be unique and contain no colons. Returns `201` with `service_id`, `api_key`, `admin_user_id`. Save `api_key` — returned only once, valid 7 days.

## `GET /service/<service_id>`
Get service info. Bearer token required. Returns `200` with `service_name`, `creation_time`, `api_key_expiration_time`.

## `PUT /service/<service_id>`
Rename service. Bearer token required. Body: `{"new_service_name": "..."}`. New name cannot match current name, cannot contain colons. Returns `200`.

## `DELETE /service/<service_id>`
Delete service (cascades to users and rules). Bearer token required. Returns `200`.

---

## `POST /service/<service_id>/token/rotate`
Rotate API key. No bearer token — authenticated by admin credentials. Body: `{"user_id": "...", "password": "..."}`. User must be admin of the service. Returns `200` with new `token`. Old key is immediately invalidated; new key expires in 7 days.

---

## `POST /user`
Create user. Bearer token required. Body: `{"service_id": "...", "password": "...", "is_admin": false}`. `is_admin` defaults to `false`. Returns `201` with `user_id`.

## `GET /user/<user_id>`
Get user info. Bearer token (admin) OR user's own credentials. Body: `{"service_id": "...", "password": "..."}`. Returns `200` with `service_id`, `is_admin`, `creation_time`.

## `PUT /user/<user_id>`
Update password. Bearer token (admin) OR user's own credentials. Body: `{"service_id": "...", "password": "...", "new_password": "..."}`. New password cannot match current. Returns `200`.

## `DELETE /user/<user_id>`
Delete user. Bearer token required. Cannot delete last admin user (`403`). Returns `200`.

---

## `POST /rule`
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

`domain`, `category`, `identifier` cannot contain colons. `(domain, category, identifier)` must be unique. `window_size` and `rate_limit` must be positive. `algorithm` must be one of: `token_bucket`, `leaking_bucket`, `fixed_window`, `sliding_window_log`, `sliding_window_counter`. Returns `201`.

## `GET /rule`
Get rule config. Bearer token required. Body: `{"domain": "...", "category": "...", "identifier": "..."}`. Returns `200` with `window_size`, `rate_limit`, `algorithm`.

## `PUT /rule`
Update rule. Bearer token required. Same body shape as GET, plus new values for any of `window_size`, `rate_limit`, `algorithm`. At least one field must change. Returns `200`.

## `DELETE /rule`
Delete rule. Bearer token required. Body: `{"domain": "...", "category": "...", "identifier": "..."}`. Returns `200`.

---

## `POST /redirect`
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

**Response 200** (leaking bucket, queued): `{"status": 202}`. The 202 in the body means the request was accepted for async processing.

**Response 429**: `{"error": "Rate limit exceeded"}`.

**Response 400**: Invalid `redirect_method`, non-dict `redirect_args`/`redirect_params`, or validation error.

**Response 401**: Invalid user credentials.

**Response 502**: Upstream request failed.
