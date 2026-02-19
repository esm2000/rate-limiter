import datetime
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

def test_check_if_request_is_allowed_token_bucket_not_allowed():
    pass

def test_check_if_request_is_allowed_leaking_bucket_allowed_on_first_attempt():
    pass

def test_check_if_request_is_allowed_leaking_bucket_allowed():
    pass

def test_check_if_request_is_allowed_leaking_bucket_not_allowed():
    pass

def test_check_if_request_is_allowed_fixed_window_allowed_on_first_attempt():
    pass

def test_check_if_request_is_allowed_fixed_window_allowed():
    pass

def test_check_if_request_is_allowed_fixed_window_not_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_log_allowed_on_first_attempt():
    pass

def test_check_if_request_is_allowed_sliding_window_log_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_log_not_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_counter_allowed_on_first_attempt():
    pass

def test_check_if_request_is_allowed_sliding_window_counter_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_counter_not_allowed():
    pass

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
