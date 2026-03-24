import uuid
from datetime import datetime, timezone, timedelta

from db import get_data_from_database, alter_database


def insert_service(name):
    service_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expiration = now + timedelta(days=7)
    alter_database(
        "INSERT INTO services (id, name, creation_time, api_key_expiration_time, api_key_hash) "
        "VALUES (%s, %s, %s, %s, %s)",
        (service_id, name, now, expiration, "fakehash"),
    )
    return service_id


def test_get_data_from_database_returns_rows_matching_parameterized_query(clean_db):
    insert_service("alpha")
    insert_service("beta")

    rows = get_data_from_database("SELECT name FROM services WHERE name = %s", ("alpha",))

    assert len(rows) == 1
    assert rows[0][0] == "alpha"


def test_get_data_from_database_returns_empty_list_when_no_rows_match_query_params(clean_db):
    rows = get_data_from_database("SELECT * FROM services WHERE name = %s", ("nonexistent",))

    assert rows == []


def test_alter_database_inserts_row_that_is_subsequently_returned_by_get_data(clean_db):
    service_id = insert_service("gamma")

    rows = get_data_from_database("SELECT id, name FROM services WHERE id = %s", (service_id,))

    assert len(rows) == 1
    assert str(rows[0][0]) == service_id
    assert rows[0][1] == "gamma"


def test_alter_database_updates_existing_row_and_change_is_reflected_on_query(clean_db):
    service_id = insert_service("old_name")

    alter_database("UPDATE services SET name = %s WHERE id = %s", ("new_name", service_id))

    rows = get_data_from_database("SELECT name FROM services WHERE id = %s", (service_id,))
    assert len(rows) == 1
    assert rows[0][0] == "new_name"


def test_alter_database_deletes_row_and_row_is_absent_on_subsequent_query(clean_db):
    service_id = insert_service("to_delete")

    alter_database("DELETE FROM services WHERE id = %s", (service_id,))

    rows = get_data_from_database("SELECT * FROM services WHERE id = %s", (service_id,))
    assert rows == []
