import datetime
import uuid
from werkzeug.exceptions import Unauthorized
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