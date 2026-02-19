import datetime
import json
import pytest
import uuid
from unittest.mock import patch
from werkzeug.exceptions import BadRequest, Unauthorized

from throttle import check_if_request_is_allowed
from hash import hash

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
        mapping={}  # log unchanged; queue not stored until increment
    )
    mock_pipe.expire.assert_called_once_with(
        f"{domain}:{category}:{identifier}:{user_id}",
        5 + 60  # window_size + 60
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
        5 + 60  # window_size + 60
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
        5 + 60  # window_size + 60
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
    pass

def test_manage_leaking_bucket_queues_refreshes_queue_after_30_seconds():
    pass

def test_manage_leaking_bucket_queues_acquires_refresh_lock_before_refresh():
    pass

def test_manage_leaking_bucket_queues_handles_refresh_failure_gracefully():
    pass

def test_manage_leaking_bucket_queues_processes_rule_from_queue():
    pass

def test_manage_leaking_bucket_queues_waits_when_queue_empty():
    pass

def test_manage_leaking_bucket_queues_returns_rule_to_queue_on_lock_failure():
    pass

def test_manage_leaking_bucket_queues_returns_rule_to_queue_after_processing():
    pass

def test_manage_leaking_bucket_queues_processes_request_when_outflow_due():
    pass

def test_manage_leaking_bucket_queues_skips_processing_when_outflow_not_due():
    pass

def test_manage_leaking_bucket_queues_handles_empty_request_queue():
    pass

def test_manage_leaking_bucket_queues_makes_http_request_with_correct_params():
    pass

def test_manage_leaking_bucket_queues_retries_failed_requests():
    pass

def test_manage_leaking_bucket_queues_updates_queue_after_successful_request():
    pass

def test_manage_leaking_bucket_queues_updates_last_outflow_time():
    pass

def test_manage_leaking_bucket_queues_stops_when_shutdown_signal_set():
    pass

def test_manage_leaking_bucket_queues_releases_lock_on_exception():
    pass
