import datetime
import json
import pytest
import uuid
from contextlib import contextmanager
from unittest.mock import patch, MagicMock, call
from werkzeug.exceptions import BadRequest, Unauthorized

import throttle as throttle_module
from throttle import check_if_request_is_allowed, manage_leaking_bucket_queues, LEAKING_BUCKET_QUEUE_KEY, LEAKING_BUCKET_REFRESH_LOCK_KEY
from hash import hash


_UNSET = object()

@contextmanager
def throttle_state(last_refresh=_UNSET):
    """Context manager to safely set and restore _last_refresh for testing."""
    if last_refresh is _UNSET:
        last_refresh = datetime.datetime.now()
    saved = throttle_module._last_refresh
    throttle_module._last_refresh = last_refresh
    try:
        yield
    finally:
        throttle_module._last_refresh = saved


# Queue key convention for tests that need a rule from the queue
TEST_KEY = "test_domain:test_cat:test_id:user_123:10"

def test_check_if_request_is_allowed_with_invalid_credentials(mock_db):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "wrong_password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.return_value = [(hash("correct_password"),)]

    with pytest.raises(Unauthorized):
        check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

def test_check_if_request_is_allowed_with_non_existent_service(mock_db):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        []
    ]

    with pytest.raises(BadRequest):
        check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

def test_check_if_request_is_allowed_with_non_existent_rule(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        []
    ]

    mock_cache.get.return_value = None

    with pytest.raises(BadRequest):
        check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

def test_check_if_request_is_allowed_token_bucket_allowed_on_first_attempt(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket size of 10 requests
        # refill rate of 5 minutes
        [(10, 5 * 60, "token_bucket")]
    ]

    mock_cache.hgetall.return_value = {
        "last_request_time": None,
        "last_token_count": "0"
    }

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "last_request_time": current_time.isoformat(),
            "last_token_count": "10"
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        5 * 60 + 60  # rate_limit + 60 (token bucket uses rate_limit as TTL base)
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_token_bucket_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket size of 10 requests
        # refill rate of 5 minutes
        [(10, 5 * 60, "token_bucket")]
    ]

    mock_cache.hgetall.return_value = {
        "last_request_time": (current_time - datetime.timedelta(seconds=4*60)).isoformat(),
        "last_token_count": "6"
    }

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "last_request_time": current_time.isoformat(),
            "last_token_count": "6"  # 6 + int(240/300)= 0 tokens added, not yet consumed
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        5 * 60 + 60  # rate_limit + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_token_bucket_not_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket size of 10, refill rate of 5 minutes
        [(10, 5 * 60, "token_bucket")]
    ]

    mock_cache.hgetall.return_value = {
        "last_request_time": (current_time - datetime.timedelta(seconds=10)).isoformat(),
        "last_token_count": "0"  # empty bucket, not enough time elapsed to refill
    }

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "last_request_time": current_time.isoformat(),
            "last_token_count": "0"  # int(10/300) = 0 tokens added
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        5 * 60 + 60  # rate_limit + 60
    )

    assert not is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_leaking_bucket_allowed_on_first_attempt(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket capacity of 5, outflow rate of 10 seconds
        [(5, 10, "leaking_bucket")]
    ]

    mock_cache.hgetall.return_value = {}  # no prior state

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"queue": "[]"}  # queue initialized
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        10 + 60  # rate_limit (outflow) + 60
    )

    assert is_allowed
    assert is_leaking_bucket

def test_check_if_request_is_allowed_leaking_bucket_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket capacity of 5, outflow rate of 10 seconds
        [(5, 10, "leaking_bucket")]
    ]

    existing_queue = json.dumps([
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}},
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}},
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
    ])
    mock_cache.hgetall.return_value = {"queue": existing_queue}

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"queue": existing_queue}  # log unchanged in check phase
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        10 + 60  # rate_limit (outflow) + 60
    )

    assert is_allowed
    assert is_leaking_bucket

def test_check_if_request_is_allowed_leaking_bucket_not_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # bucket capacity of 5, outflow rate of 10 seconds
        [(5, 10, "leaking_bucket")]
    ]

    # 6 items exceeds bucket capacity of 5 (5 >= 6 is False)
    full_queue = json.dumps([
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
        for _ in range(6)
    ])
    mock_cache.hgetall.return_value = {"queue": full_queue}

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"queue": full_queue}
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        10 + 60  # rate_limit (outflow) + 60
    )

    assert not is_allowed
    assert is_leaking_bucket

def test_check_if_request_is_allowed_fixed_window_allowed_on_first_attempt(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "fixed_window")]
    ]

    mock_cache.hgetall.return_value = {}  # no prior state

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "fw_time_window_start": current_time.isoformat(),
            "fw_num_requests": "0"  # not yet consumed
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_fixed_window_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "fixed_window")]
    ]

    time_window_start = current_time - datetime.timedelta(seconds=30)
    mock_cache.hgetall.return_value = {
        "fw_time_window_start": time_window_start.isoformat(),
        "fw_num_requests": "5"
    }

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "fw_time_window_start": time_window_start.isoformat(),
            "fw_num_requests": "5"  # unchanged, not yet consumed
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_fixed_window_not_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "fixed_window")]
    ]

    time_window_start = current_time - datetime.timedelta(seconds=30)
    mock_cache.hgetall.return_value = {
        "fw_time_window_start": time_window_start.isoformat(),
        "fw_num_requests": "10"  # at rate limit
    }

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "fw_time_window_start": time_window_start.isoformat(),
            "fw_num_requests": "10"  # unchanged
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert not is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_log_allowed_on_first_attempt(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "sliding_window_log")]
    ]

    mock_cache.hgetall.return_value = {}  # no prior state

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"timestamps": ""}  # empty after trimming empty list; not yet consumed
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_log_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "sliding_window_log")]
    ]

    # 5 timestamps within the window
    timestamps = [
        (current_time - datetime.timedelta(seconds=i * 10)).isoformat()
        for i in range(1, 6)
    ]
    mock_cache.hgetall.return_value = {"timestamps": "|||".join(timestamps)}

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"timestamps": "|||".join(timestamps)}  # all within window, unchanged
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_log_not_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 5 requests
        [(60, 5, "sliding_window_log")]
    ]

    # 5 timestamps within the window — at rate limit, so +1 would exceed it
    timestamps = [
        (current_time - datetime.timedelta(seconds=i * 10)).isoformat()
        for i in range(1, 6)
    ]
    mock_cache.hgetall.return_value = {"timestamps": "|||".join(timestamps)}

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"timestamps": "|||".join(timestamps)}  # unchanged
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert not is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_counter_allowed_on_first_attempt(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "sliding_window_counter")]
    ]

    mock_cache.hgetall.return_value = {}  # no prior state

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={"swc_time_window_start": current_time.isoformat()}
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_counter_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "sliding_window_counter")]
    ]

    time_window_start = current_time - datetime.timedelta(seconds=30)
    time_window_start_str = time_window_start.isoformat()
    previous_window_start_str = (time_window_start - datetime.timedelta(seconds=60)).isoformat()

    mock_cache.hgetall.return_value = {
        "swc_time_window_start": time_window_start_str,
        time_window_start_str: "4",       # 4 requests in current window
        previous_window_start_str: "6"   # 6 requests in previous window
    }

    # overlap_ratio = 1 - (30/60) = 0.5
    # num_requests = floor(4 + 6*0.5) = 7 < 10 → allowed

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "swc_time_window_start": time_window_start_str,
            time_window_start_str: "4",
            previous_window_start_str: "6"
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert is_allowed
    assert not is_leaking_bucket

def test_check_if_request_is_allowed_sliding_window_counter_not_allowed(mock_db, mock_cache):
    _, _, mock_cur = mock_db
    domain = str(uuid.uuid4())
    category = "test_category"
    identifier = "test_identifier"
    user_id = str(uuid.uuid4())
    password = "password"
    current_time = datetime.datetime.now()

    mock_cur.fetchall.side_effect = [
        [(user_id,)],
        [(hash(password),)],
        [(domain,)],
        # time window of 60 seconds, rate limit of 10 requests
        [(60, 10, "sliding_window_counter")]
    ]

    time_window_start = current_time - datetime.timedelta(seconds=30)
    time_window_start_str = time_window_start.isoformat()
    previous_window_start_str = (time_window_start - datetime.timedelta(seconds=60)).isoformat()

    mock_cache.hgetall.return_value = {
        "swc_time_window_start": time_window_start_str,
        time_window_start_str: "8",       # 8 requests in current window
        previous_window_start_str: "8"   # 8 requests in previous window
    }

    # overlap_ratio = 1 - (30/60) = 0.5
    # num_requests = floor(8 + 8*0.5) = 12 >= 10 → not allowed

    is_allowed, is_leaking_bucket = check_if_request_is_allowed(domain, category, identifier, user_id, password, current_time)

    mock_pipe = mock_cache.pipeline.return_value
    mock_pipe.hset.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        mapping={
            "swc_time_window_start": time_window_start_str,
            time_window_start_str: "8",
            previous_window_start_str: "8"
        }
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        60 + 60  # window_size + 60
    )

    assert not is_allowed
    assert not is_leaking_bucket

def test_manage_leaking_bucket_queues_initializes_last_refresh():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=None), \
         patch('throttle.time.sleep'):
        with throttle_state(last_refresh=None):
            manage_leaking_bucket_queues()
            assert throttle_module._last_refresh is not None

def test_manage_leaking_bucket_queues_refreshes_queue_after_30_seconds():
    stale = datetime.datetime.now() - datetime.timedelta(seconds=31)
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.refresh_leaking_bucket_queue') as mock_refresh, \
         patch('throttle.pop_from_list', return_value=None), \
         patch('throttle.time.sleep'):
        with throttle_state(last_refresh=stale):
            manage_leaking_bucket_queues()

        mock_refresh.assert_called_once()

def test_manage_leaking_bucket_queues_acquires_refresh_lock_before_refresh():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True) as mock_acquire, \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=None), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        assert mock_acquire.call_args_list[0] == call(LEAKING_BUCKET_REFRESH_LOCK_KEY, timeout=5)

def test_manage_leaking_bucket_queues_handles_refresh_failure_gracefully():
    stale = datetime.datetime.now() - datetime.timedelta(seconds=31)
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.refresh_leaking_bucket_queue', side_effect=Exception("DB error")), \
         patch('throttle.pop_from_list', return_value=None), \
         patch('throttle.time.sleep') as mock_sleep:
        with throttle_state(last_refresh=stale):
            manage_leaking_bucket_queues()

        mock_sleep.assert_called_once_with(1)

def test_manage_leaking_bucket_queues_processes_rule_from_queue():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=None) as mock_pop, \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_pop.assert_called_once_with(LEAKING_BUCKET_QUEUE_KEY)

def test_manage_leaking_bucket_queues_waits_when_queue_empty():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=None), \
         patch('throttle.time.sleep') as mock_sleep:
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_sleep.assert_called_once_with(1)

def test_manage_leaking_bucket_queues_returns_rule_to_queue_on_lock_failure():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', side_effect=[True, False]), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.push_to_list') as mock_push, \
         patch('throttle.time.sleep') as mock_sleep:
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_push.assert_called_once_with(LEAKING_BUCKET_QUEUE_KEY, TEST_KEY)
        mock_sleep.assert_called_once_with(1)

def test_manage_leaking_bucket_queues_returns_rule_to_queue_after_processing():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=5)).isoformat()

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": "[]", "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.push_to_list') as mock_push, \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_push.assert_called_once_with(LEAKING_BUCKET_QUEUE_KEY, TEST_KEY)

def test_manage_leaking_bucket_queues_processes_request_when_outflow_due():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()
    request_info = {"url": "http://ex.com", "method": "GET", "params": {}, "args": {}}
    queue = json.dumps([request_info])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.requests.request') as mock_request, \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_request.assert_called_once()

def test_manage_leaking_bucket_queues_skips_processing_when_outflow_not_due():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=5)).isoformat()
    request_info = {"url": "http://ex.com", "method": "GET", "params": {}, "args": {}}
    queue = json.dumps([request_info])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.requests.request') as mock_request, \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_request.assert_not_called()

def test_manage_leaking_bucket_queues_handles_empty_request_queue():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": "[]", "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.requests.request') as mock_request, \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_request.assert_not_called()

def test_manage_leaking_bucket_queues_makes_http_request_with_correct_params():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()
    request_info = {"url": "http://example.com/api", "method": "POST", "params": {"q": "test"}, "args": {"key": "val"}}
    queue = json.dumps([request_info])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.requests.request') as mock_request, \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_request.assert_called_once_with(
            method="POST",
            url="http://example.com/api",
            params={"q": "test"},
            json={"key": "val"},
            timeout=30
        )

def test_manage_leaking_bucket_queues_retries_failed_requests():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()
    request_info = {"url": "http://ex.com", "method": "GET", "params": {}, "args": {}}
    queue = json.dumps([request_info])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash'), \
         patch('throttle.requests.request', side_effect=[Exception("network error"), Exception("network error"), MagicMock()]) as mock_request, \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        assert mock_request.call_count == 3

def test_manage_leaking_bucket_queues_updates_queue_after_successful_request():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()
    two_item_queue = json.dumps([
        {"url": "http://a.com", "method": "GET", "params": {}, "args": {}},
        {"url": "http://b.com", "method": "GET", "params": {}, "args": {}}
    ])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": two_item_queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash') as mock_store, \
         patch('throttle.requests.request', return_value=MagicMock()), \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        stored_log = mock_store.call_args[0][1]
        stored_queue = json.loads(stored_log["queue"])
        assert len(stored_queue) == 1
        assert stored_queue[0]["url"] == "http://b.com"

def test_manage_leaking_bucket_queues_updates_last_outflow_time():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    last_outflow_time = (datetime.datetime.now() - datetime.timedelta(seconds=11)).isoformat()
    request_info = {"url": "http://ex.com", "method": "GET", "params": {}, "args": {}}
    queue = json.dumps([request_info])

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock'), \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', return_value={"queue": queue, "last_outflow_time": last_outflow_time}), \
         patch('throttle.store_hash') as mock_store, \
         patch('throttle.requests.request', return_value=MagicMock()), \
         patch('throttle.push_to_list'), \
         patch('throttle.time.sleep'):
        with throttle_state():
            manage_leaking_bucket_queues()

        stored_log = mock_store.call_args[0][1]
        stored_outflow = datetime.datetime.fromisoformat(stored_log["last_outflow_time"])
        assert abs((stored_outflow - datetime.datetime.now()).total_seconds()) < 2

def test_manage_leaking_bucket_queues_stops_when_shutdown_signal_set():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.return_value = True

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.pop_from_list') as mock_pop:
        with throttle_state():
            manage_leaking_bucket_queues()

        mock_pop.assert_not_called()

def test_manage_leaking_bucket_queues_releases_lock_on_exception():
    mock_shutdown = MagicMock()
    mock_shutdown.is_set.side_effect = [False, True]

    with patch.object(throttle_module, '_shutdown', mock_shutdown), \
         patch('throttle.acquire_lock', return_value=True), \
         patch('throttle.release_lock') as mock_release, \
         patch('throttle.pop_from_list', return_value=TEST_KEY), \
         patch('throttle.retrieve_hash', side_effect=RuntimeError("crash")), \
         patch('throttle.time.sleep'), \
         patch('throttle.push_to_list') as mock_push:
        with throttle_state():
            manage_leaking_bucket_queues()

        lock_key = "lock:test_domain:test_cat:test_id:user_123"
        calls = mock_release.call_args_list
        assert any(c == call(lock_key) for c in calls)
        # rule is re-enqueued even after an exception
        mock_push.assert_called_once_with(LEAKING_BUCKET_QUEUE_KEY, TEST_KEY)

# TODO: Add increment_rate_limit_usage test stubs for each algorithm:
# - token_bucket (consumes a token after successful redirect)
# - leaking_bucket (appends request to queue)
# - fixed_window (increments num_requests)
# - sliding_window_log (appends timestamp for all attempts)
# - sliding_window_counter (increments current window count and purges old keys)
