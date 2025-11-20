import datetime
import pytest
import util
import uuid
from werkzeug.exceptions import BadRequest, Conflict, NotFound, Unauthorized

from hash import hash

def test_is_valid_uuid(mock_db):
    assert util.is_valid_uuid(str(uuid.uuid4()))

    assert not util.is_valid_uuid(uuid.uuid4())
    assert not util.is_valid_uuid("")
    assert not util.is_valid_uuid(str(uuid.uuid4()) + "9")
    assert not util.is_valid_uuid(str(uuid.uuid4())[:-1])

def test_validate_api_token(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is for API key verification
        [(hash(token),)],
        # second call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    util.validate_api_token(auth_header, service_id)

def test_validate_api_token_with_incorrect_token(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is for API key verification
        [(hash(token + '_'),)],
        # second call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    with pytest.raises(Unauthorized):
        util.validate_api_token(auth_header, service_id)

def test_validate_api_token_with_expired_token(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is for API key verification
        [(hash(token),)],
        # second call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),)]
    ]
    with pytest.raises(Unauthorized):
        util.validate_api_token(auth_header, service_id)

def test_validate_user_id(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())

    mock_cur.fetchall.return_value = [(user_id,)]

    util.validate_user_id(user_id)

def test_validate_user_id_with_invalid_user_id(mock_db):
    _, _, mock_cur = mock_db

    user_id = ""
    mock_cur.fetchall.return_value = [(user_id,)]
    with pytest.raises(BadRequest):
        util.validate_user_id(user_id)

    user_id = None
    mock_cur.fetchall.return_value = [(user_id,)]
    with pytest.raises(BadRequest):
        util.validate_user_id(user_id)

def test_validate_user_id_with_non_existent_user(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())

    mock_cur.fetchall.return_value = []

    with pytest.raises(NotFound):
        util.validate_user_id(user_id)

def test_validate_user_input(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.return_value = [(user_id,)]
    
    util.validate_user_input(user_id, password)

def test_validate_user_input_with_invalid_password(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    
    password = ""
    mock_cur.fetchall.return_value = [(user_id,)]
    with pytest.raises(BadRequest):
        util.validate_user_input(user_id, password)

    password = None
    mock_cur.fetchall.return_value = [(user_id,)]
    with pytest.raises(BadRequest):
        util.validate_user_input(user_id, password)

    password = 59
    mock_cur.fetchall.return_value = [(user_id,)]
    with pytest.raises(BadRequest):
        util.validate_user_input(user_id, password)

def test_is_valid_user_id_and_password(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.return_value = [(hash(password),)]

    assert util.is_valid_user_id_and_password(user_id, password)

def test_is_valid_user_id_and_password_with_incorrect_password(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.return_value = [(hash(password) + "-",)]

    assert not util.is_valid_user_id_and_password(user_id, password)

def test_validate_user_id_and_password(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.return_value = [(hash(password),)]

    util.validate_user_id_and_password(user_id, password)

def test_validate_user_id_and_password_with_incorrect_password(mock_db):
    _, _, mock_cur = mock_db
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.return_value = [(hash(password) + "-",)]

    with pytest.raises(Unauthorized):
        util.validate_user_id_and_password(user_id, password)

def test_validate_auth_or_password_with_auth(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = None

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to comfirm that the user_id exists
        [(user_id,)],
        # fifth call is to confirm that the user belongs to the provided service
        [(user_id,)]
    ]

    util.validate_auth_or_password(auth_header, service_id, user_id, password)

def test_validate_auth_or_password_with_auth_and_no_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    
    user_id = str(uuid.uuid4())
    password = None

    service_id = None
    
    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to comfirm that the user_id exists
        [(user_id,)],
        # fifth call is to confirm that the user belongs to the provided service
        [(user_id,)]
    ]
    with pytest.raises(BadRequest):
        util.validate_auth_or_password(auth_header, service_id, user_id, password)

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to comfirm that the user_id exists
        [(user_id,)],
        # fifth call is to confirm that the user belongs to the provided service
        [(user_id,)]
    ]

    service_id = ""

    with pytest.raises(BadRequest):
        util.validate_auth_or_password(auth_header, service_id, user_id, password)


def test_validate_auth_or_password_with_auth_and_nonexistent_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = None

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to comfirm that the user_id exists
        [(user_id,)],
        # fifth call is to confirm that the user belongs to the provided service
        [(user_id,)]
    ]

    with pytest.raises(BadRequest):
        util.validate_auth_or_password(auth_header, service_id, user_id, password)

def test_validate_auth_or_password_that_does_not_belong_to_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = None

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to comfirm that the user_id exists
        [(user_id,)],
        # fifth call is to confirm that the user belongs to the provided service
        []
    ]

    with pytest.raises(BadRequest):
        util.validate_auth_or_password(auth_header, service_id, user_id, password)

def test_validate_auth_or_password_with_password(mock_db):
    _, _, mock_cur = mock_db
    auth_header = None
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = "password"

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the user exists
        [(user_id,)],
        # second call is to validate the username-password combination
        [(hash(password),)]
    ]

    util.validate_auth_or_password(auth_header, service_id, user_id, password)

def test_validate_auth_for_service(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    util.validate_auth_for_service(auth_header, service_id)

def test_validate_auth_for_service_with_no_auth_header(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    service_id = str(uuid.uuid4())

    auth_header = ""
    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]
    with pytest.raises(Unauthorized):
        util.validate_auth_for_service(auth_header, service_id)
    
    auth_header = None
    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]
    with pytest.raises(Unauthorized):
        util.validate_auth_for_service(auth_header, service_id)

def test_validate_auth_for_service_with_invalid_auth_header(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bear {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    with pytest.raises(Unauthorized):
        util.validate_auth_for_service(auth_header, service_id)

def test_validate_auth_for_service_with_no_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    
    service_id = ""
    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]
    with pytest.raises(BadRequest):
        util.validate_auth_for_service(auth_header, service_id)

        _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    
    service_id = None
    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]
    with pytest.raises(BadRequest):
        util.validate_auth_for_service(auth_header, service_id)

def test_validate_auth_for_service_with_nonexistent_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to validate that the service exists
        [],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    with pytest.raises(BadRequest):
        util.validate_auth_for_service(auth_header, service_id)

def test_validate_category_identifier_combination(mock_db):
    _, _, mock_cur = mock_db
    category = "test_category"
    identifier = "test_identifier"
    domain = "test_domain"

    mock_cur.fetchall.return_value = []

    util.validate_category_identifier_combination(
        category,
        identifier,
        domain
    )

def test_validate_category_identifier_combination_with_existing_combination(mock_db):
    _, _, mock_cur = mock_db
    category = "test_category"
    identifier = "test_identifier"
    domain = "test_domain"

    mock_cur.fetchall.return_value = [(category, identifier, domain)]

    with pytest.raises(Conflict):
        util.validate_category_identifier_combination(
            category,
            identifier,
            domain
        )

def test_validate_rate_limit():
    rate_limit = 5
    util.validate_rate_limit(rate_limit)

def test_validate_rate_limit_with_negative_rate_limit():
    rate_limit = -5
    with pytest.raises(BadRequest):
        util.validate_rate_limit(rate_limit)

def test_validate_rate_limit_with_non_numerical_rate_limit():
    rate_limit = "10"
    with pytest.raises(BadRequest):
        util.validate_rate_limit(rate_limit)

def test_validate_algorithm():
    for algorithm in ["token_bucket", "leaky_bucket", "fixed_window", "sliding_window_log", "sliding_window_counter"]:
        util.validate_algorithm(algorithm)

def test_validate_algorithm_with_invalid_algorithm():
    algorithm = "random"
    with pytest.raises(BadRequest):
        util.validate_algorithm(algorithm)

def test_get_rule_from_database(mock_db):
    _, _, mock_cur = mock_db
    window_size = 3600
    rate_limit = 5
    algorithm = "token_bucket"
    category = "test_category"
    identifier = "test_identifier"
    domain = str(uuid.uuid4())

    mock_cur.fetchall.return_value = [(window_size, rate_limit, algorithm)]
    
    assert util.get_rule_from_database(category, identifier, domain) == (window_size, rate_limit, algorithm)

def test_get_rule_from_database_with_non_existent_rule(mock_db):
    _, _, mock_cur = mock_db
    category = "test_category"
    identifier = "test_identifier"
    domain = str(uuid.uuid4())
   
    mock_cur.fetchall.return_value = []

    with pytest.raises(BadRequest):
        util.get_rule_from_database(category, identifier, domain)
    

def test_validate_service_exists(mock_db):
    _, _, mock_cur = mock_db
    service_id = str(uuid.uuid4())
    domain = "test_domain"

    mock_cur.fetchall.return_value = [(service_id,)]

    util.validate_service_exists(service_id, domain)

def test_validate_service_exists_with_service_id_only(mock_db):
    _, _, mock_cur = mock_db
    service_id = str(uuid.uuid4())
    domain = None

    mock_cur.fetchall.return_value = [(service_id,)]

    util.validate_service_exists(service_id, domain)

def test_validate_service_exists_with_non_existent_service(mock_db):
    _, _, mock_cur = mock_db
    service_id = str(uuid.uuid4())
    domain = "test_domain"

    mock_cur.fetchall.return_value = []

    with pytest.raises(BadRequest):
        util.validate_service_exists(service_id, domain)

def test_validate_auth_header_present_and_not_malformed():
    auth_header = "Bearer fake_token"
    util.validate_auth_header_present_and_not_malformed(auth_header)

def test_validate_auth_header_present_and_not_malformed_with_nonexistent_auth_header():
    auth_header = None
    with pytest.raises(Unauthorized):
        util.validate_auth_header_present_and_not_malformed(auth_header)

def test_validate_auth_header_present_and_not_malformed_with_malformed_auth_header():
    auth_header = "fake_token"
    with pytest.raises(Unauthorized):
        util.validate_auth_header_present_and_not_malformed(auth_header)