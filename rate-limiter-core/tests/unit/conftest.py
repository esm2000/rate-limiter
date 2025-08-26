import pytest
from unittest.mock import patch, MagicMock
import uuid

@pytest.fixture
def mock_db():
    with patch('psycopg2.connect') as mock_connect:
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cur
        yield mock_connect, mock_conn, mock_cur

def is_valid_uuid(uuid_string):
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False