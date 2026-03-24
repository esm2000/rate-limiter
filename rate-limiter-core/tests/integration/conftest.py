import os
import sys

import psycopg2
import pytest
import redis

sys.path.insert(0, os.path.dirname(__file__))


@pytest.fixture(scope="session")
def redis_client():
    client = redis.Redis(
        host=os.getenv("REDIS_HOST", "cache"),
        port=6379,
        password=os.getenv("REDIS_PASSWORD"),
        decode_responses=True,
    )
    yield client
    client.flushdb()


@pytest.fixture
def clean_redis(redis_client):
    yield
    redis_client.flushdb()


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


