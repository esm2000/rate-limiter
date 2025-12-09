import datetime
import pytest
from unittest.mock import patch
import uuid
from werkzeug.exceptions import BadRequest

from hash import hash
from rule import create_rule, get_rule_info, update_rule, delete_rule

def test_create_rule(mock_db):
    # test all possible algorithms
    for algorithm in ["token_bucket", "leaking_bucket", "fixed_window", "sliding_window_log", "sliding_window_counter"]:
        fake_token = "fake_token"
        auth_header = f"Bearer {fake_token}"
        domain = "test_service"
        category = "test_category"
        identifier = "test_identifier"
        window_size = 86400 # seconds in a day
        rate_limit = 100
        
        _, _, mock_cur = mock_db
        mock_cur.fetchall.side_effect = [
            # first call is for service lookup
            [(str(uuid.uuid4()),)],
            # second call is for api key verification
            [(hash(fake_token),)],
            # third call is to check if the api key is expired
            [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
            # fourth call is to check if category identifier combination exists already
            []
        ]

        create_rule(
            auth_header,
            domain,
            category,
            identifier,
            window_size,
            rate_limit,
            algorithm
        )

def test_create_rule_with_missing_information(mock_db):
    # test all possible keys
    skips = ["domain", "category", "identifier", "window_size", "rate_limit", "algorithm"]
    
    for skip in skips:
        for empty_value in [None, ""]:
            fake_token = "fake_token"
            auth_header = f"Bearer {fake_token}"
            domain = "test_service" if skip != "domain" else empty_value
            category = "test_category" if skip != "category" else empty_value
            identifier = "test_identifier" if skip != "identifier" else empty_value
            window_size = 86400 if skip != "window_size" else empty_value
            rate_limit = 100 if skip != "rate_limit" else empty_value
            algorithm = "token_bucket" if skip != "algorithm" else empty_value
            
            _, _, mock_cur = mock_db
            mock_cur.fetchall.side_effect = [
                # first call is for service lookup
                [(str(uuid.uuid4()),)],
                # second call is for api key verification
                [(hash(fake_token),)],
                # third call is to check if the api key is expired
                [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
                # fourth call is to check if category identifier combination exists already
                []
            ]

            with pytest.raises(BadRequest):
                create_rule(
                    auth_header,
                    domain,
                    category,
                    identifier,
                    window_size,
                    rate_limit,
                    algorithm
                )

def test_get_rule_info(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_catgory"
    identifier = "test_identifier"

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(86400, 100, "token_bucket")]
    ]

    window_size, rate_limit, algorithm = get_rule_info(
        auth_header,
        domain,
        category,
        identifier
    )

    assert window_size == 86400
    assert rate_limit == 100
    assert algorithm == "token_bucket"

def test_update_rule(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"

    old_window_size = 3600
    new_window_size = 86400

    old_rate_limit = 5
    new_rate_limit = 100

    old_algorithm = "token_bucket"
    new_algorithm = "fixed_window"

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(old_window_size, old_rate_limit, old_algorithm)]
    ]

    update_rule(
        auth_header,
        domain,
        category,
        identifier,
        new_window_size,
        new_rate_limit,
        new_algorithm
    )

def test_update_rule_with_no_changes_for_window_size(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"

    old_window_size = 3600
    new_window_size = None

    old_rate_limit = 5
    new_rate_limit = 100

    old_algorithm = "token_bucket"
    new_algorithm = "fixed_window"

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(old_window_size, old_rate_limit, old_algorithm)]
    ]

    update_rule(
        auth_header,
        domain,
        category,
        identifier,
        new_window_size,
        new_rate_limit,
        new_algorithm
    )

def test_update_rule_with_no_changes_for_rate_limit(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"

    old_window_size = 3600
    new_window_size = 86400

    old_rate_limit = 5
    new_rate_limit = None

    old_algorithm = "token_bucket"
    new_algorithm = "fixed_window"

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(old_window_size, old_rate_limit, old_algorithm)]
    ]

    update_rule(
        auth_header,
        domain,
        category,
        identifier,
        new_window_size,
        new_rate_limit,
        new_algorithm
    )

def test_update_rule_with_no_changes_for_algorithm(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"

    old_window_size = 3600
    new_window_size = 86400

    old_rate_limit = 5
    new_rate_limit = 100

    old_algorithm = "token_bucket"
    new_algorithm = None

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(old_window_size, old_rate_limit, old_algorithm)]
    ]

    update_rule(
        auth_header,
        domain,
        category,
        identifier,
        new_window_size,
        new_rate_limit,
        new_algorithm
    )

def test_update_rule_with_no_changes(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"

    old_window_size = 3600
    new_window_size = None

    old_rate_limit = 5
    new_rate_limit = None

    old_algorithm = "token_bucket"
    new_algorithm = None

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(old_window_size, old_rate_limit, old_algorithm)]
    ]

    with pytest.raises(BadRequest):
        update_rule(
            auth_header,
            domain,
            category,
            identifier,
            new_window_size,
            new_rate_limit,
            new_algorithm
        )

def test_delete_rule(mock_db):
    fake_token = "fake_token"
    auth_header = f"Bearer {fake_token}"
    domain = "test_service"
    category = "test_category"
    identifier = "test_identifier"


    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(str(uuid.uuid4()),)],
        # second call is for api key verification
        [(hash(fake_token),)],
        # third call is to check if the api key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is for the rule lookup
        [(86400, 100, "token_bucket")]
    ]

    delete_rule(
        auth_header,
        domain,
        category,
        identifier
    )

# TODO: test helper methods in test_util