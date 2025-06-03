import uuid

def is_valid_uuid(value: str) -> bool:
    try:
        uuid_obj = uuid.UUID(value, version=4)
        return str(uuid_obj) == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False