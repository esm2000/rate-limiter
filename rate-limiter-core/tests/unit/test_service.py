import datetime
import pytest
from unittest.mock import patch
import uuid
from werkzeug.exceptions import BadRequest, Conflict, Unauthorized

from hash import hash
from service import create_service, renew_api_token, update_service, get_service_info, delete_service
from .test_util import is_valid_uuid

@patch("secrets.token_urlsafe")
def test_create_service(mock_token, mock_db):
    _, _, mock_cur = mock_db
    mock_cur.fetchall.return_value = []

    mock_token.return_value = "fake_token"

    service_id, api_key, user_id = create_service("test_service", "password")

    assert is_valid_uuid(service_id)
    assert api_key == "fake_token"
    assert is_valid_uuid(user_id)

def test_create_service_with_invalid_service_name():
    with pytest.raises(BadRequest):
        create_service(None, "password")

    with pytest.raises(BadRequest):
        create_service(6885, "password")

def test_create_service_with_existing_service_name(mock_db):
    _, _, mock_cur = mock_db
    mock_cur.fetchall.return_value = [("test_service",)]

    with pytest.raises(Conflict):
        create_service("test_service", "password")

def test_create_service_with_invalid_admin_password(mock_db):
    _, _, mock_cur = mock_db
    mock_cur.fetchall.return_value = []

    with pytest.raises(BadRequest):
        create_service("test_service", None)

    with pytest.raises(BadRequest):
        create_service("test_service", 4875)

@patch("secrets.token_urlsafe")
def test_renew_api_token(mock_token, mock_db):
    user_id = str(uuid.uuid4())
    password = "fake_password"
    password_hash = hash(password)
    service_id = str(uuid.uuid4())

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password verification
        [(password_hash,)],
        # third call is to check if the user is an admin of the service
        [(True, service_id)]
    ]

    mock_token.return_value = "fake_token"

    api_key = renew_api_token(service_id, user_id, password)
    assert api_key == "fake_token"

def test_renew_api_token_with_non_admin_user(mock_db):
    user_id = str(uuid.uuid4())
    password = "fake_password"
    password_hash = hash(password)
    service_id = str(uuid.uuid4())

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password verification
        [(password_hash,)],
        # third call is to check if the user is an admin of the service
        [(False, service_id)]
    ]

    with pytest.raises(Unauthorized):
        renew_api_token(service_id, user_id, password)

def test_renew_api_token_with_admin_user_for_a_different_service(mock_db):
    user_id = str(uuid.uuid4())
    password = "fake_password"
    password_hash = hash(password)
    service_id = str(uuid.uuid4())
    other_service_id = str(uuid.uuid4())

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password verification
        [(password_hash,)],
        # third call is to check if the user is an admin of the service
        [(True, other_service_id)]
    ]

    with pytest.raises(Unauthorized):
        renew_api_token(service_id, user_id, password)

def test_update_service(mock_db):
    service_id = str(uuid.uuid4())
    api_key = "fake_token"
    auth_header = f"Bearer {api_key}"
    api_key_hash = hash(api_key)
    new_service_name = "new_service_name"

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is to check if the new service name is different from the old one
        [("test_service",)]
    ]

    update_service(auth_header, service_id, new_service_name)

def test_update_service_with_invalid_new_service_name_given(mock_db):
    service_id = str(uuid.uuid4())
    api_key = "fake_token"
    auth_header = f"Bearer {api_key}"
    api_key_hash = hash(api_key)

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)]
    ]
    with pytest.raises(BadRequest):
        update_service(auth_header, service_id, None)
    
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)]
    ]

    with pytest.raises(BadRequest):
        update_service(auth_header, service_id, 49485)

def test_update_service_with_same_service_name(mock_db):
    service_id = str(uuid.uuid4())
    api_key = "fake_token"
    auth_header = f"Bearer {api_key}"
    api_key_hash = hash(api_key)

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)],
        # fourth call is to check if the new service name is different from the old one
        [("test_service",)]
    ]

    with pytest.raises(BadRequest):
        update_service(auth_header, service_id, "test_service")

def test_get_service_info(mock_db):
    service_id = str(uuid.uuid4())
    api_key = "fake_token"
    auth_header = f"Bearer {api_key}"
    api_key_hash = hash(api_key)
    service_name = "test_service"
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    expiration_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(expiration_time,)],
        # fourth call is to retrieve service info
        [(service_name, creation_time, expiration_time)]
    ]

    retrieved_service_name, retrieved_creation_time, retrieved_expiration_time = get_service_info(auth_header, service_id)
    assert retrieved_service_name == service_name
    assert retrieved_creation_time == creation_time
    assert retrieved_expiration_time == expiration_time

def test_delete_service(mock_db):
    service_id = str(uuid.uuid4())
    api_key = "fake_token"
    auth_header = f"Bearer {api_key}"
    api_key_hash = hash(api_key)

    _, _, mock_cur = mock_db
    mock_cur.fetchall.side_effect = [
        # first call is to check if the service exists
        [(service_id,)],
        # second call is to check if the API key is valid
        [(api_key_hash,)],
        # third call is to check if the API key is expired
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),)]
    ]

    delete_service(auth_header, service_id)