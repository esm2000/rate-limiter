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
        raise Unauthorized(f"Invalid API key provided ({api_key})")
    
    api_key_expiration_time = get_data_from_database(f"SELECT api_key_expiration_time FROM services WHERE id = %s", (service_id, ))[0][0].replace(tzinfo=ZoneInfo("UTC"))
    if api_key_expiration_time < datetime.datetime.now(datetime.timezone.utc):
        raise Unauthorized("API key has expired")

def validate_user_id(user_id):
    if not is_valid_uuid(user_id) or not user_id or not isinstance(user_id, str):
        raise BadRequest("Invalid input for user_id")

    if not get_data_from_database("SELECT id FROM users WHERE id = %s", (user_id,)):
        raise NotFound(f"User {user_id} not found")
    
def validate_user_input(user_id, password):
    validate_user_id(user_id)
    
    if not password or not isinstance(password, str):
        raise BadRequest("Invalid input for password")

def validate_user_id_and_password(user_id, password):
    password_hash = get_data_from_database(f"SELECT password_hash FROM users WHERE id = %s", (user_id,))[0][0]

    if not verify(password, password_hash):
        raise Unauthorized("Invalid password used")