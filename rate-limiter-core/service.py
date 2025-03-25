import datetime
import secrets
import uuid
from werkzeug.exceptions import Conflict

from hash import hash, verify
from db import get_data_from_database, alter_database


def create_service(
    service_name,
    admin_user_password
):
    # check if there's already an existing service with that name
    if get_data_from_database(f"SELECT id FROM services WHERE name = %s", (service_name,)):
        raise Conflict(f"Service with name {service_name} already exists.")

    # gather service details
    service_id = uuid.uuid4()
    creation_time = datetime.datetime.now(datetime.timezone.utc)
    api_key_expiration_time = creation_time + datetime.timedelta(days=7)
    api_key = secrets.token_urlsafe(32)
    api_key_hash = hash(api_key)

    # gather admin user details
    user_id = uuid.uuid4()
    hashed_admin_user_password = hash(admin_user_password)

    alter_database(
        """
        INSERT INTO services (id, name, creation_time, api_key_expiration_time, api_key_hash)
        VALUES (%s, %s, %s, %s, %s);
        
        INSERT INTO users (id, service_id, is_admin, creation_time, password_hash)
        VALUES (%s, %s, TRUE, %s, %s);
        """,
        (
            service_id, creation_time, api_key_expiration_time, api_key_hash,
            user_id, service_id, creation_time, hashed_admin_user_password
        )
    )

    return service_id, api_key, user_id

def update_service():
    # ensure that user is an admin
    pass

def get_service_info():
    # ensure user is an admin
    pass