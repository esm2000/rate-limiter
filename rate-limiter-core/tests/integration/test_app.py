import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


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


# Health check

def test_health_check_get_returns_200_and_service_name(flask_client):
    resp = flask_client.get("/")
    assert resp.status_code == 200
    assert resp.data == b"rate-limiter-core"


# Service lifecycle

def test_create_service_post_returns_201_with_service_id_api_key_and_admin_user_id(flask_client, clean_db):
    resp = flask_client.post("/service", json={
        "service_name": "test-svc", "admin_password": "admin-pass"
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert "service_id" in data
    assert "api_key" in data
    assert "admin_user_id" in data


def test_create_service_post_with_name_that_already_exists_returns_409(flask_client, clean_db):
    create_service_via_api(flask_client, "duplicate-svc", "admin-pass")
    resp = flask_client.post("/service", json={
        "service_name": "duplicate-svc", "admin_password": "admin-pass"
    })
    assert resp.status_code == 409


def test_get_service_info_with_valid_bearer_token_returns_200_and_name_and_timestamps(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.get(f"/service/{service_id}",
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["service_name"] == "test-svc"
    assert "creation_time" in data
    assert "api_key_expiration_time" in data


def test_get_service_info_with_invalid_bearer_token_returns_401(flask_client, clean_db):
    service_id, _, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.get(f"/service/{service_id}",
        headers={"Authorization": "Bearer invalid-token"})
    assert resp.status_code == 401


def test_get_service_info_for_nonexistent_service_id_returns_400(flask_client, clean_db):
    fake_id = str(uuid.uuid4())
    resp = flask_client.get(f"/service/{fake_id}",
        headers={"Authorization": "Bearer fake-token"})
    assert resp.status_code == 400


def test_update_service_name_with_valid_bearer_token_returns_200_and_new_name(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "old-name", "admin-pass")
    resp = flask_client.put(f"/service/{service_id}",
        json={"new_service_name": "new-name"},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["service_name"] == "new-name"


def test_update_service_name_to_same_current_name_returns_400(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "same-name", "admin-pass")
    resp = flask_client.put(f"/service/{service_id}",
        json={"new_service_name": "same-name"},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 400


def test_delete_service_with_valid_bearer_token_returns_200(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.delete(f"/service/{service_id}",
        json={},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    resp2 = flask_client.get(f"/service/{service_id}",
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp2.status_code == 400


def test_rotate_api_token_with_admin_user_id_and_password_returns_200_and_new_token(flask_client, clean_db):
    service_id, api_key, admin_user_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.post(f"/service/{service_id}/token/rotate", json={
        "user_id": admin_user_id, "password": "admin-pass"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "token" in data
    assert data["token"] != api_key


def test_rotate_api_token_with_non_admin_user_credentials_returns_401(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.post(f"/service/{service_id}/token/rotate", json={
        "user_id": user_id, "password": "user-pass"
    })
    assert resp.status_code == 401


# User lifecycle

def test_create_user_with_valid_bearer_token_returns_201_and_user_id(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.post("/user", json={
        "service_id": service_id, "password": "user-pass", "is_admin": False
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 201
    assert "user_id" in resp.get_json()


def test_create_user_without_authorization_header_returns_401(flask_client, clean_db):
    service_id, _, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.post("/user", json={
        "service_id": service_id, "password": "user-pass", "is_admin": False
    })
    assert resp.status_code == 401


def test_create_user_for_nonexistent_service_id_returns_400(flask_client, clean_db):
    fake_id = str(uuid.uuid4())
    resp = flask_client.post("/user", json={
        "service_id": fake_id, "password": "user-pass", "is_admin": False
    }, headers={"Authorization": "Bearer fake-token"})
    assert resp.status_code == 400


def test_get_user_info_as_admin_with_bearer_token_returns_200_and_correct_fields(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.get(f"/user/{user_id}",
        json={"service_id": service_id},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user_id"] == user_id
    assert data["service_id"] == service_id
    assert data["is_admin"] is False
    assert "creation_time" in data


def test_get_user_info_as_self_with_correct_password_returns_200(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.get(f"/user/{user_id}",
        json={"password": "user-pass"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user_id"] == user_id
    assert data["service_id"] == service_id


def test_update_user_password_as_self_with_correct_current_password_returns_200(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.put(f"/user/{user_id}",
        json={"password": "user-pass", "new_password": "new-pass"})
    assert resp.status_code == 200


def test_update_user_password_as_admin_with_bearer_token_returns_200(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.put(f"/user/{user_id}",
        json={"service_id": service_id, "new_password": "new-pass"},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200


def test_update_user_password_to_same_current_password_returns_400(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.put(f"/user/{user_id}",
        json={"password": "user-pass", "new_password": "user-pass"})
    assert resp.status_code == 400


def test_delete_user_as_admin_with_valid_bearer_token_returns_200(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    user_id = create_user_via_api(flask_client, api_key, service_id, "user-pass", is_admin=False)
    resp = flask_client.delete(f"/user/{user_id}",
        json={"service_id": service_id},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200


def test_delete_last_admin_user_for_a_service_returns_403(flask_client, clean_db):
    service_id, api_key, admin_user_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = flask_client.delete(f"/user/{admin_user_id}",
        json={"service_id": service_id},
        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 403


# Rule lifecycle

@pytest.mark.parametrize("algorithm", [
    "token_bucket", "leaking_bucket", "fixed_window",
    "sliding_window_log", "sliding_window_counter"
])
def test_create_rule_with_each_of_the_five_algorithms_returns_201(flask_client, clean_db, algorithm):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, algorithm)
    assert resp.status_code == 201


def test_create_rule_with_duplicate_domain_category_identifier_combination_returns_409(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    assert resp.status_code == 409


def test_create_rule_with_colon_in_domain_category_or_identifier_returns_400(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = create_rule_via_api(flask_client, api_key, service_id, "cat:egory", "endpoint", 10, 3600, "token_bucket")
    assert resp.status_code == 400


def test_get_rule_info_returns_correct_window_size_rate_limit_and_algorithm(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.get("/rule", json={
        "domain": service_id, "category": "api", "identifier": "endpoint"
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["window_size"] == 3600
    assert data["rate_limit"] == 10
    assert data["algorithm"] == "token_bucket"


def test_update_rule_with_new_fields_returns_200_and_change_is_persisted_in_database(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.put("/rule", json={
        "domain": service_id, "category": "api", "identifier": "endpoint",
        "rate_limit": 20
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    get_resp = flask_client.get("/rule", json={
        "domain": service_id, "category": "api", "identifier": "endpoint"
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert get_resp.get_json()["rate_limit"] == 20


def test_delete_rule_returns_200_and_rule_is_no_longer_retrievable(flask_client, clean_db):
    service_id, api_key, _ = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.delete("/rule", json={
        "domain": service_id, "category": "api", "identifier": "endpoint"
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    get_resp = flask_client.get("/rule", json={
        "domain": service_id, "category": "api", "identifier": "endpoint"
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert get_resp.status_code == 400


# Redirect endpoint — algorithm enforcement

def _make_redirect(client, service_id, user_id, password, category="api", identifier="endpoint"):
    return client.post("/redirect", json={
        "domain": service_id, "category": category, "identifier": identifier,
        "redirect_url": "http://example.com", "redirect_method": "GET",
        "user_id": user_id, "password": password
    })


def test_redirect_returns_200_when_request_is_within_token_bucket_limit(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    mock_resp = MagicMock(status_code=200, text="OK")
    with patch("app.requests.request", return_value=mock_resp), \
         patch("app.increment_rate_limit_usage"):
        resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_redirect_returns_429_when_token_bucket_is_exhausted(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 1, 3600, "token_bucket")
    now = datetime.now(timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "last_token_count": "0",
        "last_request_time": now.isoformat()
    })
    redis_client.expire(key, 600)
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 429


def test_redirect_returns_200_when_request_is_within_fixed_window_limit(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "fixed_window")
    mock_resp = MagicMock(status_code=200, text="OK")
    with patch("app.requests.request", return_value=mock_resp), \
         patch("app.increment_rate_limit_usage"):
        resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_redirect_returns_429_when_fixed_window_request_count_reaches_rate_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 1, 3600, "fixed_window")
    now = datetime.now(timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "1",
        "fw_time_window_start": now.isoformat()
    })
    redis_client.expire(key, 600)
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 429


def test_redirect_resets_fixed_window_counter_and_allows_request_after_window_duration_elapses(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 1, 1, "fixed_window")
    two_seconds_ago = datetime.now(timezone.utc) - timedelta(seconds=2)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={
        "fw_num_requests": "1",
        "fw_time_window_start": two_seconds_ago.isoformat()
    })
    redis_client.expire(key, 600)
    mock_resp = MagicMock(status_code=200, text="OK")
    with patch("app.requests.request", return_value=mock_resp), \
         patch("app.increment_rate_limit_usage"):
        resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_redirect_returns_200_when_request_is_within_sliding_window_log_limit(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "sliding_window_log")
    mock_resp = MagicMock(status_code=200, text="OK")
    with patch("app.requests.request", return_value=mock_resp), \
         patch("app.increment_rate_limit_usage"):
        resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_redirect_returns_429_when_sliding_window_log_is_at_rate_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 1, 3600, "sliding_window_log")
    now = datetime.now(timezone.utc)
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={"timestamps": now.isoformat()})
    redis_client.expire(key, 600)
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 429


def test_redirect_returns_200_when_request_is_within_sliding_window_counter_rolling_estimate(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "sliding_window_counter")
    mock_resp = MagicMock(status_code=200, text="OK")
    with patch("app.requests.request", return_value=mock_resp), \
         patch("app.increment_rate_limit_usage"):
        resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_redirect_returns_429_when_sliding_window_counter_rolling_estimate_exceeds_limit(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 1, 3600, "sliding_window_counter")
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    key = f"{service_id}:api:endpoint:{admin_id}"
    redis_client.hset(key, mapping={"swc_time_window_start": now_str, now_str: "1"})
    redis_client.expire(key, 600)
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 429


def test_redirect_returns_202_and_enqueues_request_when_leaking_bucket_queue_is_below_capacity(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 5, "leaking_bucket")
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 202
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue = json.loads(redis_client.hget(key, "queue"))
    assert len(queue) == 1
    assert queue[0]["url"] == "http://example.com"


def test_redirect_returns_429_when_leaking_bucket_queue_is_at_capacity(flask_client, clean_db, clean_redis, redis_client):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 1, "leaking_bucket")
    key = f"{service_id}:api:endpoint:{admin_id}"
    queue = [
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}},
        {"url": "http://example.com", "method": "GET", "params": {}, "args": {}}
    ]
    redis_client.hset(key, mapping={"queue": json.dumps(queue)})
    redis_client.expire(key, 600)
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass")
    assert resp.status_code == 429


# Redirect endpoint — input validation

def test_redirect_with_invalid_user_credentials_returns_401(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = _make_redirect(flask_client, service_id, admin_id, "wrong-pass")
    assert resp.status_code == 401


def test_redirect_with_nonexistent_rule_returns_400(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    resp = _make_redirect(flask_client, service_id, admin_id, "admin-pass",
                          category="nonexistent", identifier="nothing")
    assert resp.status_code == 400


def test_redirect_with_unsupported_redirect_method_returns_400(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.post("/redirect", json={
        "domain": service_id, "category": "api", "identifier": "endpoint",
        "redirect_url": "http://example.com", "redirect_method": "INVALID",
        "user_id": admin_id, "password": "admin-pass"
    })
    assert resp.status_code == 400


def test_redirect_with_non_dict_redirect_args_returns_400(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.post("/redirect", json={
        "domain": service_id, "category": "api", "identifier": "endpoint",
        "redirect_url": "http://example.com", "redirect_method": "GET",
        "redirect_args": "not_a_dict",
        "user_id": admin_id, "password": "admin-pass"
    })
    assert resp.status_code == 400


def test_redirect_with_non_dict_redirect_params_returns_400(flask_client, clean_db, clean_redis):
    service_id, api_key, admin_id = create_service_via_api(flask_client, "test-svc", "admin-pass")
    create_rule_via_api(flask_client, api_key, service_id, "api", "endpoint", 10, 3600, "token_bucket")
    resp = flask_client.post("/redirect", json={
        "domain": service_id, "category": "api", "identifier": "endpoint",
        "redirect_url": "http://example.com", "redirect_method": "GET",
        "redirect_params": "not_a_dict",
        "user_id": admin_id, "password": "admin-pass"
    })
    assert resp.status_code == 400
