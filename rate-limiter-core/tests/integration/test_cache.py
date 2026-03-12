import time

from cache import (
    store_value,
    retrieve_value,
    increment_value,
    decrement_value,
    store_hash,
    retrieve_hash,
    push_to_list,
    pop_from_list,
    clear_list,
    acquire_lock,
    release_lock,
)


def test_store_value_and_retrieve_value_roundtrip(redis_client, clean_redis):
    store_value("test:key", "hello", 60)
    assert retrieve_value("test:key") == "hello"


def test_retrieve_value_returns_none_for_nonexistent_key(redis_client, clean_redis):
    assert retrieve_value("test:nonexistent") is None


def test_store_value_with_ttl_key_expires_after_ttl_elapses(redis_client, clean_redis):
    store_value("test:ttl", "ephemeral", 1)
    assert retrieve_value("test:ttl") == "ephemeral"
    time.sleep(1.1)
    assert retrieve_value("test:ttl") is None


def test_increment_value_creates_key_starting_at_one_when_key_does_not_exist(redis_client, clean_redis):
    increment_value("test:inc_new")
    assert retrieve_value("test:inc_new") == "1"


def test_increment_value_increments_existing_key_by_one_on_each_call(redis_client, clean_redis):
    store_value("test:inc", "5", 60)
    increment_value("test:inc")
    increment_value("test:inc")
    assert retrieve_value("test:inc") == "7"


def test_decrement_value_decrements_existing_key_by_one(redis_client, clean_redis):
    store_value("test:dec", "10", 60)
    decrement_value("test:dec")
    assert retrieve_value("test:dec") == "9"


def test_store_hash_and_retrieve_hash_roundtrip_preserves_all_fields(redis_client, clean_redis):
    data = {"field_a": "1", "field_b": "two", "field_c": "3.0"}
    store_hash("test:hash", data, 60)
    assert retrieve_hash("test:hash") == data


def test_retrieve_hash_returns_empty_dict_for_nonexistent_key(redis_client, clean_redis):
    assert retrieve_hash("test:hash_missing") == {}


def test_store_hash_with_ttl_hash_expires_after_ttl_elapses(redis_client, clean_redis):
    store_hash("test:hash_ttl", {"k": "v"}, 1)
    assert retrieve_hash("test:hash_ttl") == {"k": "v"}
    time.sleep(1.1)
    assert retrieve_hash("test:hash_ttl") == {}


def test_push_to_list_and_pop_from_list_behave_as_fifo_queue(redis_client, clean_redis):
    push_to_list("test:queue", "first")
    push_to_list("test:queue", "second")
    push_to_list("test:queue", "third")
    assert pop_from_list("test:queue") == "first"
    assert pop_from_list("test:queue") == "second"
    assert pop_from_list("test:queue") == "third"


def test_pop_from_list_returns_none_when_list_is_empty(redis_client, clean_redis):
    assert pop_from_list("test:empty_list") is None


def test_clear_list_removes_all_elements_from_an_existing_list(redis_client, clean_redis):
    push_to_list("test:clearme", "a")
    push_to_list("test:clearme", "b")
    clear_list("test:clearme")
    assert pop_from_list("test:clearme") is None


def test_acquire_lock_returns_true_when_no_lock_is_currently_held(redis_client, clean_redis):
    assert acquire_lock("test:lock1", timeout=5) is True


def test_acquire_lock_returns_false_when_lock_is_already_held_by_another_caller(redis_client, clean_redis):
    acquire_lock("test:lock2", timeout=10)
    assert acquire_lock("test:lock2", timeout=10) is None


def test_release_lock_deletes_key_allowing_subsequent_acquisition_to_succeed(redis_client, clean_redis):
    acquire_lock("test:lock3", timeout=10)
    release_lock("test:lock3")
    assert acquire_lock("test:lock3", timeout=10) is True


def test_acquire_lock_expires_automatically_after_the_specified_timeout_without_release(redis_client, clean_redis):
    acquire_lock("test:lock4", timeout=1)
    assert acquire_lock("test:lock4", timeout=1) is None
    time.sleep(1.1)
    assert acquire_lock("test:lock4", timeout=5) is True
