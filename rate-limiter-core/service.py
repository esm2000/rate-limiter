import datetime
import secrets
import uuid
from werkzeug.exceptions import BadRequest, Conflict, NotFound, Unauthorized

from hash import hash, verify
from db import get_data_from_database, alter_database
from util import is_valid_uuid


def create_service(
    service_name,
    admin_user_password
):
    
    if not service_name or not isinstance(service_name, str):
        raise BadRequest("Invalid input for service_name")
    
    # check if there's already an existing service with that name
    if get_data_from_database(f"SELECT id FROM services WHERE name = %s", (service_name,)):
        raise Conflict(f"Service with name {service_name} already exists.")
    
    if not admin_user_password or not isinstance(admin_user_password, str):
        raise BadRequest("Invalid input for admin_user_password")

    # gather service details
    service_id = str(uuid.uuid4())
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    api_key_expiration_time = creation_time + datetime.timedelta(days=7)
    api_key = secrets.token_urlsafe(32)
    api_key_hash = hash(api_key)

    # gather admin user details
    user_id = str(uuid.uuid4())
    hashed_admin_user_password = hash(admin_user_password)

    alter_database(
        """
        INSERT INTO services (id, name, creation_time, api_key_expiration_time, api_key_hash)
        VALUES (%s, %s, %s, %s, %s);
        
        INSERT INTO users (id, service_id, is_admin, creation_time, password_hash)
        VALUES (%s, %s, TRUE, %s, %s);
        """,
        (
            service_id, service_name, creation_time, api_key_expiration_time, api_key_hash,
            user_id, service_id, creation_time, hashed_admin_user_password
        )
    )

    return service_id, api_key, user_id

def renew_api_token(service_id, user_id, password):
    if not is_valid_uuid(user_id) or not user_id or not isinstance(user_id, str):
        raise BadRequest("Invalid input for user_id")

    if not get_data_from_database("SELECT id FROM users WHERE id = %s", (user_id,)):
        raise NotFound(f"User {user_id} not found")
    
    if not password or not isinstance(password, str):
        raise BadRequest("Invalid input for password")

    # retrieve password hash for user
    password_hash = get_data_from_database(f"SELECT password_hash FROM users WHERE id = %s", (user_id,))[0][0]

    if not verify(password, password_hash):
        raise Unauthorized("Invalid password used")
    
    # check that user is admin of the service being altered
    is_admin, service_of_user = get_data_from_database(f"SELECT is_admin, service_id FROM users WHERE id = %s", (user_id,))[0]
    
    if not is_admin or service_of_user != service_id:
        raise Unauthorized(f"User is not admin of service {service_id}")

    creation_time = datetime.datetime.now(datetime.timezone.utc)
    api_key_expiration_time = creation_time + datetime.timedelta(days=7)
    api_key = secrets.token_urlsafe(32)
    api_key_hash = hash(api_key)

    alter_database(
        """
        UPDATE services
        SET api_key_hash = %s, api_key_expiration_time = %s
        WHERE id = %s
        """,
        (api_key_hash, api_key_expiration_time, service_id)
    )

    return api_key

def update_service():
    # ensure that user is an admin
    pass

def get_service_info():
    # ensure user is an admin
    pass