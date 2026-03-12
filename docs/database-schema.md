# Database Schema

Defined in `database/init.sql`. Table creation order follows FK dependencies: `services` before `users`, `services` before `rules`.

## `services`

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

## `users`

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

## `rules`

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
