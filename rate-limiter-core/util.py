import datetime
import uuid
from werkzeug.exceptions import BadRequest, Conflict, NotFound, Unauthorized
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


def validate_category_identifier_combination(category, identifier, domain):
    existing_rule = get_data_from_database(
        "SELECT id FROM rules WHERE category = %s AND identifier = %s AND domain = %s", 
        (category, identifier, domain)
    )
    if existing_rule:
        raise Conflict(f"Rule with category '{category}' and identifier '{identifier}' already exists for domain '{domain}'")

def validate_rate_limit_unit(rate_limit_unit):
    valid_units = ["second", "minute", "hour", "day"]
    if rate_limit_unit not in valid_units:
        raise BadRequest(f"Invalid rate_limit_unit '{rate_limit_unit}'. Must be one of: {', '.join(valid_units)}")

def validate_rate_limit(rate_limit):
    if not isinstance(rate_limit, (int, float)) or rate_limit <= 0:
        raise BadRequest("rate_limit must be a positive number greater than 0")

def validate_algorithm(algorithm):
    valid_algorithms = ["token_bucket", "leaky_bucket", "fixed_window", "sliding_window_log", "sliding_window_counter"]
    if algorithm not in valid_algorithms:
        raise BadRequest(f"Invalid algorithm '{algorithm}'. Must be one of: {', '.join(valid_algorithms)}")

def get_rule_from_database(category, identifier, domain):
    data = get_data_from_database(
        """
        SELECT rate_limit_unit, rate_limit, algorithm
        FROM rules
        WHERE category = %s AND identifier = %s AND domain = %s
        """,
        (category, identifier, domain)
    )

    if not data:
        raise BadRequest(f"Rule with category {category} and identifier {identifier} for domain {domain} does not exist")
    
    return data[0]

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