CREATE TABLE rules (
    domain VARCHAR PRIMARY KEY,
    category VARCHAR PRIMARY KEY,
    identifier VARCHAR PRIMARY KEY,
    rate_limit_unit VARCHAR,
    rate_limit INTEGER,
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