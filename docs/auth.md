# Authentication & Authorization

## Bearer Token (API Key)

Generated with `secrets.token_urlsafe(32)` — 32 bytes of cryptographic randomness, base64url-encoded (~43 chars). Plaintext returned once (creation or rotation), never stored. Only the bcrypt hash persists in `services.api_key_hash`. Valid for 7 days.

**Validation (`validate_api_token` in `util.py`):**
1. Extract key from `Authorization: Bearer <key>`.
2. Fetch `api_key_hash` from PostgreSQL.
3. `verify(key, api_key_hash)` (bcrypt `checkpw`). Raise 401 if mismatch.
4. Check `api_key_expiration_time`. Raise 401 if expired.

## User Credentials

Users authenticate with `user_id` (UUID) + `password` (plaintext). Password hash stored with bcrypt. Validation via `validate_user_id_and_password`.

## Per-Route Authorization Matrix

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

## Validation Ordering

All protected routes:
1. Auth header present and well-formed (`validate_auth_header_present_and_not_malformed`)
2. Service exists (`validate_service_exists`)
3. API token valid (`validate_api_token`)
4. Business rules
