CREATE TABLE rules (
    domain VARCHAR,
    category VARCHAR,
    identifier VARCHAR,
    PRIMARY KEY (domain, category, identifier),
    rate_limit INTEGER,
    window_size BIGINT,
    algorithm VARCHAR
);

CREATE TABLE services (
    id UUID PRIMARY KEY,
    name VARCHAR,
    creation_time TIMESTAMP,
    api_key_expiration_time TIMESTAMP,
    api_key_hash VARCHAR
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    service_id UUID,
    is_admin BOOLEAN,
    creation_time TIMESTAMP,
    password_hash VARCHAR,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);