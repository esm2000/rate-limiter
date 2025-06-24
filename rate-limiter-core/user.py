import datetime
import uuid

from db import alter_database, get_data_from_database
from hash import hash
from util import (
    validate_api_token,
    validate_user_id,
    validate_user_id_and_password,
    validate_user_input
)
from werkzeug.exceptions import BadRequest, Unauthorized

def create_user(auth_header, service_id, is_admin, password):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    if not service_id:
        raise BadRequest("Service ID not provided")
    
    if not password:
        raise BadRequest("Password not provided for the user")
    
    # check if service exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (service_id,)):
        raise BadRequest(f"Service with ID {service_id} does not exist.")
    
    # validate API token
    validate_api_token(auth_header, service_id)
    
    # create user based on provided information
    if is_admin is None:
        is_admin = False

    user_id = str(uuid.uuid4())
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    hashed_user_password = hash(password)

    alter_database(
        """        
        INSERT INTO users (id, service_id, is_admin, creation_time, password_hash)
        VALUES (%s, %s, %s, %s, %s);
        """,
        (
            user_id, service_id, is_admin, creation_time, hashed_user_password
        )
    )

    return user_id

def update_user(auth_header, service_id, user_id, password):
    pass

def get_user_info(auth_header, service_id, user_id, password):
    # validate that admin (via API token) or that the user of interest (via user_id + password) is making the request
    if auth_header and auth_header.startswith('Bearer '):
        if not service_id:
            raise BadRequest("Service ID not provided")
        
        # check if service exists
        if not get_data_from_database("SELECT id FROM services WHERE id = %s", (service_id,)):
            raise BadRequest(f"Service with ID {service_id} does not exist.")
        
        if not get_data_from_database("SELECT id FROM users WHERE service_id = %s", (service_id,)):
            raise BadRequest(f"User does not belong to {service_id}.")

        validate_api_token(auth_header, service_id)
        validate_user_id(user_id)
    else:
        validate_user_input(user_id, password)
        validate_user_id_and_password(user_id, password)
    
    service_id, is_admin, creation_time = get_data_from_database(
        """
        SELECT service_id, is_admin, creation_time
        FROM users
        WHERE id = %s;
        """,
        (user_id, )
    )[0]

    return service_id, is_admin, creation_time