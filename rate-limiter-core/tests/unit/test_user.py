import datetime
import pytest
import uuid
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized

from hash import hash
from .conftest import is_valid_uuid
from user import create_user, get_user_info, update_user, delete_user

def test_create_normal_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    password = "password"
    is_admin = False 

    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    user_id = create_user(auth_header, service_id, is_admin, password)
    assert is_valid_uuid(user_id)

def test_create_admin_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = uuid.uuid4()
    password = "password"
    is_admin = True
    
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)]
    ]

    user_id = create_user(auth_header, service_id, is_admin, password)
    assert is_valid_uuid(user_id)

def test_create_user_with_invalid_auth_header():
    with pytest.raises(Unauthorized):
        create_user(None, str(uuid.uuid4()), False, "password")
    with pytest.raises(Unauthorized):
        create_user("fake_token", str(uuid.uuid4()), False, "password")

def test_create_user_with_no_service_id():
    with pytest.raises(BadRequest):
        create_user("Bearer fake_token", None, False, "password")

    with pytest.raises(BadRequest):
        create_user("Bearer fake_token", "", False, "password")

def test_create_user_with_no_password():
    with pytest.raises(BadRequest):
        create_user("Bearer fake_token", str(uuid.uuid4()), False, None)

    with pytest.raises(BadRequest):
        create_user("Bearer fake_token", str(uuid.uuid4()), False, "")

def test_create_user_with_nonexistent_service_id(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    password = "password"
    is_admin = True
    
    mock_cur.fetchall.return_value = []

    with pytest.raises(BadRequest):
        create_user(auth_header, service_id, is_admin, password)

def test_admin_get_user_info(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = None

    is_admin = False
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is for user lookup
        [(user_id,)],
        # fifth call is for ensuring user is associated with service
        [(user_id,)],
        # sixth call is to retrieve user info
        [(service_id, is_admin, creation_time)]
    ]

    retrieved_service_id, \
        retrieved_is_admin, \
        retrieved_creation_time = get_user_info(auth_header, service_id, user_id, password)
    assert service_id == retrieved_service_id
    assert is_admin == retrieved_is_admin
    assert creation_time == retrieved_creation_time

def test_user_get_user_info(mock_db):
    _, _, mock_cur = mock_db
    auth_header = None
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = "password"

    is_admin = False
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password validation
        [(hash(password),)],
        # third call is to retrieve user info
        [(service_id, is_admin, creation_time)]
    ]

    retrieved_service_id, \
        retrieved_is_admin, \
        retrieved_creation_time = get_user_info(auth_header, service_id, user_id, password)
    assert service_id == retrieved_service_id
    assert is_admin == retrieved_is_admin
    assert creation_time == retrieved_creation_time

def test_admin_update_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = None
    new_password = "password2"
    
    mock_cur.fetchall.side_effect = [
        # first call is for service lookup
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is for user lookup
        [(user_id,)],
        # fifth call is for ensuring user is associated with service
        [(user_id,)],
        # sixth call is to check if the current password is the same as the new one
        [(hash("password"),)]
    ]

    update_user(auth_header, service_id, user_id, password, new_password)

def test_user_update_user(mock_db):
    _, _, mock_cur = mock_db
    auth_header = None
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = "password"
    new_password = "password2"
    
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password validation
        [(hash(password),)],
    ]

    update_user(auth_header, service_id, user_id, password, new_password)

def test_update_user_with_no_new_password(mock_db):
    _, _, mock_cur = mock_db
    auth_header = None
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = "password"
    
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password validation
        [(hash(password),)]
    ]

    with pytest.raises(BadRequest):
        update_user(auth_header, service_id, user_id, password, None)

    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password validation
        [(hash(password),)],
    ]

    with pytest.raises(BadRequest):
        update_user(auth_header, service_id, user_id, password, "")

def test_update_user_with_same_password(mock_db):
    _, _, mock_cur = mock_db
    auth_header = None
    service_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    password = "password"
    
    mock_cur.fetchall.side_effect = [
        # first call is for user lookup
        [(user_id,)],
        # second call is for password validation
        [(hash(password),)]
    ]

    with pytest.raises(BadRequest):
        update_user(auth_header, service_id, user_id, password, password)

def test_delete_normal_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    user_id = str(uuid.uuid4())
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to check that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to check if the user being deleted is an admin
        [(False,)]
    ]

    delete_user(auth_header, user_id, service_id)
    
def test_delete_admin_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    user_id = str(uuid.uuid4())
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to check that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to check if the user being deleted is an admin
        [(True,)],
        # fifth call is to check number of admins for service
        [(2,)]
    ]

    delete_user(auth_header, user_id, service_id)

def test_delete_user_with_non_existent_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    user_id = str(uuid.uuid4())
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to check that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        []
    ]

    with pytest.raises(BadRequest):
        delete_user(auth_header, user_id, service_id)

def test_delete_user_only_admin_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    user_id = str(uuid.uuid4())
    service_id = str(uuid.uuid4())

    mock_cur.fetchall.side_effect = [
        # first call is to check that the service exists
        [(service_id,)],
        # second call is for API key verification
        [(hash(token),)],
        # third call is for API key expiration lookup
        [(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),)],
        # fourth call is to check if the user being deleted is an admin
        [(True,)],
        # fifth call is to check number of admins for service
        [(1,)]
    ]

    with pytest.raises(Forbidden):
        delete_user(auth_header, user_id, service_id)