import datetime
import uuid
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized
from zoneinfo import ZoneInfo

from db import get_data_from_database
from hash import verify

def is_valid_uuid(value: str) -> bool:
    try:
        uuid_obj = uuid.UUID(value, version=4)
        return str(uuid_obj) == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False 

def validate_api_token(auth_header, service_id):
    api_key = auth_header.split(" ")[1]
    api_key_hash = get_data_from_database(f"SELECT api_key_hash FROM services WHERE id = %s", (service_id, ))[0][0]
    if not verify(api_key, api_key_hash):
        raise Unauthorized(f"Invalid API key provided")
    
    api_key_expiration_time = get_data_from_database(f"SELECT api_key_expiration_time FROM services WHERE id = %s", (service_id, ))[0][0].replace(tzinfo=ZoneInfo("UTC"))
    if api_key_expiration_time < datetime.datetime.now(datetime.timezone.utc):
        raise Unauthorized("API key has expired")

def validate_user_id(user_id):
    if not is_valid_uuid(user_id) or not user_id:
        raise BadRequest("Invalid input for user_id")

    if not get_data_from_database("SELECT id FROM users WHERE id = %s", (user_id,)):
        raise NotFound(f"User {user_id} not found")
    
def validate_user_input(user_id, password):
    validate_user_id(user_id)
    
    if not password or not isinstance(password, str):
        raise BadRequest("Invalid input for password")

def is_valid_user_id_and_password(user_id, password):
    password_hash = get_data_from_database(f"SELECT password_hash FROM users WHERE id = %s", (user_id,))[0][0]
    return verify(password, password_hash)

def validate_user_id_and_password(user_id, password):
    if not is_valid_user_id_and_password(user_id, password):
        raise Unauthorized("Invalid password used")
    
def validate_auth_or_password(auth_header, service_id, user_id, password):
    # validate that admin (via API token) or that the user of interest (via user_id + password) is making the request
    if auth_header and auth_header.startswith('Bearer '):
        if not service_id:
            raise BadRequest("Service ID not provided")
        
        # check if service exists
        if not get_data_from_database("SELECT id FROM services WHERE id = %s", (service_id,)):
            raise BadRequest(f"Service with ID {service_id} does not exist.")

        validate_api_token(auth_header, service_id)
        validate_user_id(user_id)
        
        if not get_data_from_database("SELECT id FROM users WHERE service_id = %s", (service_id,)):
            raise BadRequest(f"User does not belong to {service_id}.")
    else:
        validate_user_input(user_id, password)
        validate_user_id_and_password(user_id, password)


def validate_auth_for_service(auth_header, service_id):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    if not service_id:
        raise BadRequest("Service ID not provided")
    
    # check if service exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (service_id,)):
        raise BadRequest(f"Service with ID {service_id} does not exist.")
    
    # validate API token
    validate_api_token(auth_header, service_id)