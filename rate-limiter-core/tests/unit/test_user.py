import datetime
import uuid

from hash import hash
from .test_util import is_valid_uuid
from user import create_user, get_user_info, update_user, delete_user

def test_create_normal_user(mock_db):
    _, _, mock_cur = mock_db
    token = "fake_token"
    auth_header = f"Bearer {token}"
    service_id = uuid.uuid4()
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