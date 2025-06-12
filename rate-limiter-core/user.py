import datetime
import uuid
from zoneinfo import ZoneInfo

from db import alter_database, get_data_from_database
from hash import hash, verify
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
    api_key = auth_header.split(" ")[1]
    api_key_hash = get_data_from_database(f"SELECT api_key_hash FROM services WHERE id = %s", (service_id, ))[0][0]
    if not verify(api_key, api_key_hash):
        raise Unauthorized(f"Invalid API key provided ({api_key})")
    
    api_key_expiration_time = get_data_from_database(f"SELECT api_key_expiration_time FROM services WHERE id = %s", (service_id, ))[0][0].replace(tzinfo=ZoneInfo("UTC"))
    if api_key_expiration_time < datetime.datetime.now(datetime.timezone.utc):
        raise Unauthorized("API key has expired")
    
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
    pass