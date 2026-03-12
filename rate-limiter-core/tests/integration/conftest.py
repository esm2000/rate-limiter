import os
import psycopg2
import pytest
import redis


@pytest.fixture(scope="session")
def redis_client():
    client = redis.Redis(
        host=os.getenv("REDIS_HOST", "cache"),
        port=6379,
        password=os.getenv("REDIS_PASSWORD"),
        decode_responses=True,
    )
    yield client
    client.flushall()


@pytest.fixture
def clean_redis(redis_client):
    yield
    redis_client.flushall()


@pytest.fixture(scope="session")
def pg_dsn():
    return (
        f"host={os.getenv('POSTGRES_HOST', 'database')} "
        f"port=5432 "
        f"dbname=postgres "
        f"user={os.getenv('POSTGRES_USER')} "
        f"password={os.getenv('POSTGRES_PASSWORD')}"
    )


@pytest.fixture
def flask_client():
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture
def clean_db(pg_dsn):
    yield
    with psycopg2.connect(pg_dsn) as conn:
        cur = conn.cursor()
        cur.execute("TRUNCATE services CASCADE")


def create_service_via_api(client, name, password):
    resp = client.post("/service", json={"service_name": name, "admin_password": password})
    data = resp.get_json()
    return data["service_id"], data["api_key"], data["admin_user_id"]


def create_user_via_api(client, api_key, service_id, password, is_admin=False):
    resp = client.post("/user", json={
        "service_id": service_id, "password": password, "is_admin": is_admin
    }, headers={"Authorization": f"Bearer {api_key}"})
    return resp.get_json()["user_id"]


def create_rule_via_api(client, api_key, domain, category, identifier, rate_limit, window_size, algorithm):
    return client.post("/rule", json={
        "domain": domain, "category": category, "identifier": identifier,
        "rate_limit": rate_limit, "window_size": window_size, "algorithm": algorithm
    }, headers={"Authorization": f"Bearer {api_key}"})
