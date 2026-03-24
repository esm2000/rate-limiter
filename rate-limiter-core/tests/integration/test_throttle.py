import datetime
import json
import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.exceptions import BadRequest, Unauthorized

import throttle as throttle_module
from helpers import create_service_via_api, create_user_via_api, create_rule_via_api, setup_service_and_rule
from throttle import (
    check_if_request_is_allowed,
    increment_rate_limit_usage,
    manage_leaking_bucket_queues,
    refresh_leaking_bucket_queue,
    LEAKING_BUCKET_QUEUE_KEY,
)


@contextmanager
def throttle_state(last_refresh=None):
    saved = throttle_module._last_refresh
    throttle_module._last_refresh = last_refresh if last_refresh is not None else datetime.datetime.now(datetime.timezone.utc)
    throttle_module._shutdown.clear()
    try:
        yield
    finally:
        throttle_module._last_refresh = saved
        throttle_module._shutdown.clear()


def shutdown_sleep(seconds):
    throttle_module._shutdown.set()


# check_if_request_is_allowed — token bucket

def test_check_if_request_is_allowed_token_bucket_allows_first_request_with_no_prior_redis_state(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_token_bucket_allows_request_when_bucket_has_available_tokens(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "last_token_count": "5",
        "last_request_time": (now - datetime.timedelta(seconds=10)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_token_bucket_denies_request_when_bucket_is_empty(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "last_token_count": "0",
        "last_request_time": (now - datetime.timedelta(seconds=10)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False
    assert is_leaking is False


def test_check_if_request_is_allowed_token_bucket_refills_tokens_proportional_to_elapsed_time(flask_client, clean_db, clean_redis, redis_client):
    # bucket_size=5 (window_size), refill_rate=10s (rate_limit)
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 10, 5)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "last_token_count": "0",
        "last_request_time": (now - datetime.timedelta(seconds=25)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, _ = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert redis_client.hget(key, "last_token_count") == "2"


# check_if_request_is_allowed — leaking bucket

def test_check_if_request_is_allowed_leaking_bucket_allows_first_request_with_no_prior_redis_state(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    now = datetime.datetime.now(datetime.timezone.utc)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is True


def test_check_if_request_is_allowed_leaking_bucket_allows_request_when_queue_length_is_below_window_size(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue = [{"url": "http://example.com", "method": "GET", "params": {}, "args": {}} for _ in range(3)]
    redis_client.hset(key, mapping={"queue": json.dumps(queue)})
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is True


def test_check_if_request_is_allowed_leaking_bucket_denies_request_when_queue_length_equals_window_size(flask_client, clean_db, clean_redis, redis_client):
    # window_size=3 (queue capacity); queue with 4 items exceeds capacity
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 3)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue = [{"url": "http://example.com", "method": "GET", "params": {}, "args": {}} for _ in range(4)]
    redis_client.hset(key, mapping={"queue": json.dumps(queue)})
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False
    assert is_leaking is True


# check_if_request_is_allowed — fixed window

def test_check_if_request_is_allowed_fixed_window_allows_first_request_with_no_prior_redis_state(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "fixed_window", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_fixed_window_allows_request_when_count_is_below_rate_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "fixed_window", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "5",
        "fw_time_window_start": (now - datetime.timedelta(seconds=30)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_fixed_window_denies_request_when_request_count_equals_rate_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "fixed_window", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "10",
        "fw_time_window_start": (now - datetime.timedelta(seconds=30)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False
    assert is_leaking is False


def test_check_if_request_is_allowed_fixed_window_resets_count_and_allows_request_after_window_elapses(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "fixed_window", 1, 1)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "1",
        "fw_time_window_start": (now - datetime.timedelta(seconds=2)).isoformat()
    })
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


# check_if_request_is_allowed — sliding window log

def test_check_if_request_is_allowed_sliding_window_log_allows_first_request_with_no_prior_redis_state(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_log", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_sliding_window_log_allows_request_when_in_window_timestamp_count_is_below_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_log", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    timestamps = [(now - datetime.timedelta(seconds=i * 10)).isoformat() for i in range(1, 6)]
    redis_client.hset(key, mapping={"timestamps": "|||".join(timestamps)})
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_sliding_window_log_denies_request_when_in_window_timestamp_count_equals_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_log", 5, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    timestamps = [(now - datetime.timedelta(seconds=i * 10)).isoformat() for i in range(1, 6)]
    redis_client.hset(key, mapping={"timestamps": "|||".join(timestamps)})
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False
    assert is_leaking is False


def test_check_if_request_is_allowed_sliding_window_log_excludes_timestamps_older_than_window_duration_from_count(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_log", 5, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    in_window = [(now - datetime.timedelta(seconds=i * 10)).isoformat() for i in range(1, 4)]
    out_of_window = [(now - datetime.timedelta(seconds=70 + i * 10)).isoformat() for i in range(3)]
    redis_client.hset(key, mapping={"timestamps": "|||".join(out_of_window + in_window)})
    redis_client.expire(key, 600)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


# check_if_request_is_allowed — sliding window counter

def test_check_if_request_is_allowed_sliding_window_counter_allows_first_request_with_no_prior_redis_state(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_counter", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_sliding_window_counter_allows_request_when_weighted_estimate_is_below_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_counter", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    window_start = now - datetime.timedelta(seconds=30)
    prev_start = window_start - datetime.timedelta(seconds=60)
    redis_client.hset(key, mapping={
        "swc_time_window_start": window_start.isoformat(),
        window_start.isoformat(): "4",
        prev_start.isoformat(): "6",
    })
    redis_client.expire(key, 600)
    # overlap_ratio = 1 - (30/60) = 0.5; rolling = floor(4 + 6*0.5) = 7 < 10
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is True
    assert is_leaking is False


def test_check_if_request_is_allowed_sliding_window_counter_denies_request_when_weighted_estimate_meets_or_exceeds_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_counter", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    window_start = now - datetime.timedelta(seconds=30)
    prev_start = window_start - datetime.timedelta(seconds=60)
    redis_client.hset(key, mapping={
        "swc_time_window_start": window_start.isoformat(),
        window_start.isoformat(): "8",
        prev_start.isoformat(): "8",
    })
    redis_client.expire(key, 600)
    # overlap_ratio = 0.5; rolling = floor(8 + 8*0.5) = 12 >= 10
    is_allowed, is_leaking = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False
    assert is_leaking is False


# check_if_request_is_allowed — error and lock behaviour

def test_check_if_request_is_allowed_raises_for_invalid_user_credentials(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(Unauthorized):
        check_if_request_is_allowed(
            service_id, "api", "endpoint", admin_id, "wrong-pass", now)


def test_check_if_request_is_allowed_raises_for_service_that_does_not_exist(flask_client, clean_db, clean_redis):
    _, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(BadRequest):
        check_if_request_is_allowed(
            str(uuid.uuid4()), "api", "endpoint", admin_id, "test-pass", now)


def test_check_if_request_is_allowed_raises_for_rule_that_does_not_exist(flask_client, clean_db, clean_redis):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(BadRequest):
        check_if_request_is_allowed(
            service_id, "nonexistent", "nothing", admin_id, "test-pass", now)


def test_check_if_request_is_allowed_persists_updated_algorithm_state_to_redis_after_decision(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert redis_client.hget(key, "last_token_count") == "10"
    assert redis_client.hget(key, "last_request_time") is not None
    assert redis_client.ttl(key) > 0


def test_check_if_request_is_allowed_releases_redis_lock_even_when_exception_is_raised(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    lock_key = f"lock:{key}"
    with patch("throttle.retrieve_hash", side_effect=Exception("forced")):
        with pytest.raises(Exception, match="forced"):
            check_if_request_is_allowed(
                service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert redis_client.get(lock_key) is None


# check_if_request_is_allowed — lock contention

def test_check_if_request_is_allowed_returns_false_when_redis_lock_is_already_held(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    lock_key = f"lock:{key}"
    redis_client.set(lock_key, "1", nx=True, ex=10)
    is_allowed, _ = check_if_request_is_allowed(
        service_id, "api", "endpoint", admin_id, "test-pass", now)
    assert is_allowed is False


# increment_rate_limit_usage

def test_increment_rate_limit_usage_token_bucket_decrements_last_token_count_in_redis_by_one(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "last_token_count": "5",
        "last_request_time": now.isoformat()
    })
    redis_client.expire(key, 600)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, None, None, None, None)
    assert redis_client.hget(key, "last_token_count") == "4"


def test_increment_rate_limit_usage_leaking_bucket_appends_request_details_to_queue_in_redis(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={"queue": "[]"})
    redis_client.expire(key, 600)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, "GET", "http://example.com", {"q": "1"}, {"key": "val"})
    queue = json.loads(redis_client.hget(key, "queue"))
    assert len(queue) == 1
    assert queue[0]["url"] == "http://example.com"
    assert queue[0]["method"] == "GET"
    assert queue[0]["params"] == {"q": "1"}
    assert queue[0]["args"] == {"key": "val"}


def test_increment_rate_limit_usage_fixed_window_increments_fw_num_requests_in_redis(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "fixed_window", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "3",
        "fw_time_window_start": (now - datetime.timedelta(seconds=30)).isoformat()
    })
    redis_client.expire(key, 600)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, None, None, None, None)
    assert redis_client.hget(key, "fw_num_requests") == "4"


def test_increment_rate_limit_usage_sliding_window_log_appends_current_timestamp_to_redis_log(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_log", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    existing = [
        (now - datetime.timedelta(seconds=10)).isoformat(),
        (now - datetime.timedelta(seconds=20)).isoformat(),
    ]
    redis_client.hset(key, mapping={"timestamps": "|||".join(existing)})
    redis_client.expire(key, 600)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, None, None, None, None)
    timestamps = redis_client.hget(key, "timestamps").split("|||")
    assert len(timestamps) == 3
    assert timestamps[-1] == now.isoformat()


def test_increment_rate_limit_usage_sliding_window_counter_increments_current_window_count_and_purges_old_window_keys(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "sliding_window_counter", 10, 60)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    window_start = now - datetime.timedelta(seconds=30)
    twss = window_start.isoformat()
    old_key = (window_start - datetime.timedelta(seconds=300)).isoformat()
    redis_client.hset(key, mapping={
        "swc_time_window_start": twss,
        twss: "3",
        old_key: "99",
    })
    redis_client.expire(key, 600)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, None, None, None, None)
    assert redis_client.hget(key, twss) == "4"
    assert redis_client.hget(key, "swc_time_window_start") == twss
    # store_hash deletes and re-creates the hash, so purged keys are removed
    assert redis_client.hget(key, old_key) is None


def test_increment_rate_limit_usage_releases_redis_lock_even_when_exception_is_raised(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    lock_key = f"lock:{key}"
    with patch("throttle.retrieve_hash", side_effect=Exception("forced")):
        with pytest.raises(Exception, match="forced"):
            increment_rate_limit_usage(
                service_id, "api", "endpoint", admin_id, "test-pass",
                now, True, None, None, None, None)
    assert redis_client.get(lock_key) is None


def test_increment_rate_limit_usage_skips_state_update_when_redis_lock_cannot_be_acquired(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    lock_key = f"lock:{key}"
    redis_client.hset(key, mapping={
        "last_token_count": "5",
        "last_request_time": now.isoformat()
    })
    redis_client.expire(key, 600)
    redis_client.set(lock_key, "1", nx=True, ex=10)
    increment_rate_limit_usage(
        service_id, "api", "endpoint", admin_id, "test-pass",
        now, True, None, None, None, None)
    assert redis_client.hget(key, "last_token_count") == "5"


# refresh_leaking_bucket_queue

def test_refresh_leaking_bucket_queue_populates_redis_list_with_one_entry_per_user_rule_combination(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = setup_service_and_rule(
        flask_client, "leaking_bucket", 10, 5)
    user2_id = create_user_via_api(flask_client, api_key, service_id, "user2-pass")
    refresh_leaking_bucket_queue()
    entries = redis_client.lrange(LEAKING_BUCKET_QUEUE_KEY, 0, -1)
    assert len(entries) == 2
    expected = {
        f"{service_id}:api:endpoint:{admin_id}:10",
        f"{service_id}:api:endpoint:{user2_id}:10",
    }
    assert set(entries) == expected


def test_refresh_leaking_bucket_queue_clears_existing_redis_list_entries_before_repopulating(flask_client, clean_db, clean_redis, redis_client):
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, "stale:entry:here:user:99")
    service_id, _, admin_id = setup_service_and_rule(
        flask_client, "leaking_bucket", 10, 5)
    refresh_leaking_bucket_queue()
    entries = redis_client.lrange(LEAKING_BUCKET_QUEUE_KEY, 0, -1)
    assert len(entries) == 1
    assert entries[0] == f"{service_id}:api:endpoint:{admin_id}:10"


def test_refresh_leaking_bucket_queue_results_in_empty_redis_list_when_no_leaking_bucket_rules_are_in_database(flask_client, clean_db, clean_redis, redis_client):
    setup_service_and_rule(flask_client, "token_bucket", 60, 10)
    refresh_leaking_bucket_queue()
    entries = redis_client.lrange(LEAKING_BUCKET_QUEUE_KEY, 0, -1)
    assert entries == []


# manage_leaking_bucket_queues

def test_manage_leaking_bucket_queues_fires_queued_http_request_when_outflow_interval_has_elapsed(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue_entry = f"{key}:10"
    request_info = {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
    redis_client.hset(key, mapping={
        "queue": json.dumps([request_info]),
        "last_outflow_time": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=15)).isoformat(),
    })
    redis_client.expire(key, 600)
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, queue_entry)
    mock_resp = MagicMock(status_code=200)
    with patch("throttle.requests.request", return_value=mock_resp) as mock_request, \
         patch("throttle.time.sleep", side_effect=shutdown_sleep):
        with throttle_state():
            manage_leaking_bucket_queues()
    mock_request.assert_called_once()


def test_manage_leaking_bucket_queues_does_not_fire_http_request_when_outflow_interval_has_not_yet_elapsed(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue_entry = f"{key}:10"
    request_info = {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
    redis_client.hset(key, mapping={
        "queue": json.dumps([request_info]),
        "last_outflow_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    redis_client.expire(key, 600)
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, queue_entry)
    with patch("throttle.requests.request") as mock_request, \
         patch("throttle.time.sleep", side_effect=shutdown_sleep):
        with throttle_state():
            manage_leaking_bucket_queues()
    mock_request.assert_not_called()


def test_manage_leaking_bucket_queues_removes_processed_request_from_front_of_redis_queue(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue_entry = f"{key}:10"
    req1 = {"url": "http://one.com", "method": "GET", "params": {}, "args": {}}
    req2 = {"url": "http://two.com", "method": "POST", "params": {}, "args": {}}
    redis_client.hset(key, mapping={
        "queue": json.dumps([req1, req2]),
        "last_outflow_time": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=15)).isoformat(),
    })
    redis_client.expire(key, 600)
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, queue_entry)
    mock_resp = MagicMock(status_code=200)
    with patch("throttle.requests.request", return_value=mock_resp), \
         patch("throttle.time.sleep", side_effect=shutdown_sleep):
        with throttle_state():
            manage_leaking_bucket_queues()
    remaining = json.loads(redis_client.hget(key, "queue"))
    assert len(remaining) == 1
    assert remaining[0]["url"] == "http://two.com"


def test_manage_leaking_bucket_queues_returns_rule_key_to_leaking_bucket_rule_queue_after_processing(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue_entry = f"{key}:10"
    request_info = {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
    redis_client.hset(key, mapping={
        "queue": json.dumps([request_info]),
        "last_outflow_time": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=15)).isoformat(),
    })
    redis_client.expire(key, 600)
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, queue_entry)
    mock_resp = MagicMock(status_code=200)
    with patch("throttle.requests.request", return_value=mock_resp), \
         patch("throttle.time.sleep", side_effect=shutdown_sleep):
        with throttle_state():
            manage_leaking_bucket_queues()
    entries = redis_client.lrange(LEAKING_BUCKET_QUEUE_KEY, 0, -1)
    assert queue_entry in entries


def test_manage_leaking_bucket_queues_releases_redis_lock_and_continues_when_exception_occurs(flask_client, clean_db, clean_redis, redis_client):
    service_id, _, admin_id = setup_service_and_rule(flask_client, "leaking_bucket", 10, 5)
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue_entry = f"{key}:10"
    lock_key = f"lock:{key}"
    redis_client.lpush(LEAKING_BUCKET_QUEUE_KEY, queue_entry)
    with patch("throttle.retrieve_hash", side_effect=Exception("forced")), \
         patch("throttle.time.sleep", side_effect=shutdown_sleep):
        with throttle_state():
            manage_leaking_bucket_queues()
    assert redis_client.get(lock_key) is None
    entries = redis_client.lrange(LEAKING_BUCKET_QUEUE_KEY, 0, -1)
    assert queue_entry in entries


def test_manage_leaking_bucket_queues_exits_loop_when_shutdown_event_is_set(clean_redis):
    with throttle_state():
        throttle_module._shutdown.set()
        manage_leaking_bucket_queues()
