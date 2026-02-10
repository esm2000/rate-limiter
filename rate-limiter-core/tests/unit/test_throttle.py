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

def test_check_if_request_is_allowed_token_bucket_allowed():
    pass

def test_check_if_request_is_allowed_token_bucket_not_allowed():
    pass

def test_check_if_request_is_allowed_leaking_bucket_allowed():
    pass

def test_check_if_request_is_allowed_leaking_bucket_not_allowed():
    pass

def test_check_if_request_is_allowed_fixed_window_allowed():
    pass

def test_check_if_request_is_allowed_fixed_window_not_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_log_allowed():
    pass

def test_check_if_request_is_allowed_sliding_window_log_not_allowed():
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

