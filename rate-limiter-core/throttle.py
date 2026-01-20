import datetime
import math

from cache import retrieve_hash, store_hash, acquire_lock, release_lock
from rule import get_rule_from_database, validate_service_exists
from user import validate_auth_or_password


def check_if_request_is_allowed(
    domain,
    category,
    identifier,
    user_id,
    password,
    current_time
):
    is_allowed = False
    # validate user credentials
    validate_auth_or_password(None, domain, user_id, password)
    validate_service_exists(domain, True)

    # retrieve rate_limit, window_size, and algorithm
    window_size, rate_limit, algorithm = get_rule_from_database(category, identifier, domain)
    is_leaking_bucket = algorithm == "leaking_bucket"

    # retrieve information about current usage from Redis with defaults defined 
    # TODO: ensure that all algorithms are using distinct keys for log or incorporate algoirthm into Redis key
    #       (this is to account for the edge case where an algorithm is switched for an existing category-identifier combination)
    key = f"{domain}:{category}:{identifier}:{user_id}"
    lock_key = f"lock:{key}"
    
    # Acquire lock for this specific user/rule combination
    if not acquire_lock(lock_key, timeout=2):
        # Could not acquire lock, deny request to avoid race conditions
        return False, is_leaking_bucket
    
    # utilize algorithm logic to decide whether or not request should be allowed
    try:
        log = retrieve_hash(key) or {}

        # token bucket: bucket size, refill rate (seconds)
        if algorithm == "token_bucket":
            
            # retrieve last_request_time
            last_request_time_str = log.get("last_request_time")
            last_token_count_str = log.get("last_token_count", 0)

            is_allowed, current_token_count = check_if_request_is_allowed_token_bucket(
                window_size,
                rate_limit,
                current_time,
                last_request_time_str,
                last_token_count_str
            )

            # update the cache with new state (but don't consume token yet)
            log["last_request_time"] = current_time.isoformat()
            log["last_token_count"] = str(current_token_count)
        elif algorithm == "fixed_window":
            # fixed window counter: request_limit, time window (seconds)
            time_window_start_str = log.get("time_window_start")
            num_requests_str = log.get("num_requests", "0")

            is_allowed, time_window_start, num_requests = check_if_request_is_allowed_fixed_window(
                window_size,
                rate_limit,
                current_time,
                time_window_start_str,
                num_requests_str
            )

            # update the cache with new state (but don't consume request yet)
            log["time_window_start"] = time_window_start.isoformat()
            log["num_requests"] = str(num_requests)
        elif algorithm == "sliding_window_log":
            # sliding window log: request_limit, time window
            timestamps_str = log.get("timestamps", "")

            is_allowed, trimmed_timestamps = check_if_request_is_allowed_sliding_window_log(
                window_size,
                rate_limit,
                current_time,
                timestamps_str
            )

            # update the cache with new state (but don't consume request yet)
            log["timestamps"] = "|||".join(trimmed_timestamps)
        elif algorithm == "sliding_window_counter":
            # sliding window counter: request_limit, time window
            time_window_start_str = log.get("time_window_start")

            is_allowed, time_window_start = check_if_request_is_allowed_sliding_window_counter(
                window_size,
                rate_limit,
                current_time,
                time_window_start_str,
                log
            )

            log["time_window_start"] = time_window_start.isoformat()
        # store updated state in Redis
        store_hash(key, log, window_size + 60)
    finally:
        # always release the lock
        release_lock(lock_key)
        
        # TODO: Implement leaking bucket after every other algorithms are finalized ("finalized" includes the increment functions + endpoint)
        # leaking bucket:       bucket size, outflow rate (seconds)
            # retrieve bucket_urls
            # if the amount of urls is less than the bucket size (window size) then allow request

                # # In redirect endpoint
                # if algorithm == "leaking_bucket":
                #     if bucket_has_space():
                #         add_to_queue(redirect_request)
                #         return {"status": "queued", "position": queue_position}
                #     else:
                #         return {"error": "bucket full"}, 429

                # # Separate background worker process
                # def background_worker():
                #     while True:
                #         if queue_not_empty() and time_for_next_request():
                #             request = dequeue()
                #             make_redirect_request(request)
                #             sleep(outflow_rate)
            
        
    return is_allowed, is_leaking_bucket
    

def increment_rate_limit_usage(domain, category, identifier, user_id, password, current_time, was_allowed):
    # validate user credentials
    validate_auth_or_password(None, domain, user_id, password)
    validate_service_exists(domain, True)

    # retrieve rate_limit, window_size, and algorithm
    window_size, rate_limit, algorithm = get_rule_from_database(category, identifier, domain)

    # retrieve information about current usage from Redis
    key = f"{domain}:{category}:{identifier}:{user_id}"
    lock_key = f"lock:{key}"
    
    # acquire lock for this specific user/rule combination
    if not acquire_lock(lock_key, timeout=5):
        # could not acquire lock, skip incrementing to avoid race conditions
        return
    
    try:
        log = retrieve_hash(key) or {}

        if was_allowed and algorithm == "token_bucket":
            # Consume a token after successful redirect
            current_token_count, last_request_time = increment_usage_token_bucket(
                current_time,
                log.get("last_token_count")
            )
            log["last_token_count"] = str(current_token_count)
            log["last_request_time"] = last_request_time
        elif was_allowed and algorithm == "fixed_window":
            # Increment num_requests after successful request
            num_requests = increment_usage_fixed_window(log.get("num_requests", "0"))
            log["num_requests"] = str(num_requests)
        elif algorithm == "sliding_window_log":
            # Add current time to timestamps log no matter what
            log["timestamps"] = increment_usage_sliding_window_log(
                current_time,
                log.get("timestamps", "")
            )
        elif algorithm == "sliding_window_counter":
            # Add current time to current time window and purge old keys
            log = increment_usage_sliding_window_counter(window_size, log)
        # store updated state in Redis
        store_hash(key, log, window_size + 60)
    finally:
        # always release the lock
        release_lock(lock_key)


def check_if_request_is_allowed_token_bucket(
    bucket_size,
    refill_rate,
    current_time,
    last_request_time_str,
    last_token_count_str
):
    is_allowed = False

    # if there is no request time assume a last request time that would completely reset the token bucket
    if last_request_time_str:
        last_request_time = datetime.datetime.fromisoformat(last_request_time_str)
    else:
        last_request_time = current_time - datetime.timedelta(seconds=(bucket_size*refill_rate+1))

    
    last_token_count = int(last_token_count_str) if last_token_count_str is not None else 0
    seconds_since_last_request = (current_time - last_request_time).total_seconds()

    # calculate the amount of tokens that should be in the bucket utlizing last_request_time, current_bucket_size, and refill_rate (window_size)
    tokens_to_be_added = int(seconds_since_last_request / refill_rate)
    current_token_count = last_token_count + tokens_to_be_added
    if current_token_count > bucket_size:
        current_token_count = bucket_size

    # if there is a token available then allow request
    if current_token_count > 0:
        is_allowed = True

    return is_allowed, current_token_count


def check_if_request_is_allowed_fixed_window(
    window_size,
    rate_limit,
    current_time,
    time_window_start_str,
    num_requests_str
):
    is_allowed = False

    if time_window_start_str:
        time_window_start = datetime.datetime.fromisoformat(time_window_start_str)
        num_requests = int(num_requests_str) if num_requests_str else 0
    else:
        time_window_start = current_time
        num_requests = 0

    while time_window_start + datetime.timedelta(seconds=window_size) < current_time:
        time_window_start += datetime.timedelta(seconds=window_size)
        num_requests = 0

    if num_requests < rate_limit:
        is_allowed = True

    return is_allowed, time_window_start, num_requests


def check_if_request_is_allowed_sliding_window_log(
    window_size,
    rate_limit,
    current_time,
    timestamps_str
):
    is_allowed = False

    timestamps = timestamps_str.split("|||") if timestamps_str else []
    window_start = current_time - datetime.timedelta(seconds=window_size)

    trimmed_timestamps = []

    for timestamp_string in timestamps:
        if window_start > datetime.datetime.fromisoformat(timestamp_string):
            continue
        trimmed_timestamps.append(timestamp_string)

    if len(trimmed_timestamps) + 1 <= rate_limit:
        is_allowed = True

    return is_allowed, trimmed_timestamps


def check_if_request_is_allowed_sliding_window_counter(
    window_size,
    rate_limit,
    current_time,
    time_window_start_str,
    log
):
    is_allowed = False

    if time_window_start_str:
        time_window_start = datetime.datetime.fromisoformat(time_window_start_str)
    else:
        time_window_start = current_time

    while time_window_start + datetime.timedelta(seconds=window_size) < current_time:
        time_window_start += datetime.timedelta(seconds=window_size)

    time_window_start_str = time_window_start.isoformat()

    previous_time_window_start = time_window_start - datetime.timedelta(seconds=window_size)
    previous_time_window_start_str = previous_time_window_start.isoformat()

    current_num_requests = int(log.get(time_window_start_str, "0"))
    previous_num_requests = int(log.get(previous_time_window_start_str, "0"))

    time_between_window_start_and_current_time = (current_time - time_window_start).total_seconds()
    overlap_ratio = 1 - (time_between_window_start_and_current_time / window_size)

    num_requests_in_rolling_window = math.floor(current_num_requests + previous_num_requests * overlap_ratio)

    if num_requests_in_rolling_window < rate_limit:
        is_allowed = True

    return is_allowed, time_window_start


def increment_usage_token_bucket(current_time, last_token_count_str):
    current_token_count = int(last_token_count_str) if last_token_count_str else 0
    if current_token_count > 0:
        current_token_count -= 1
    return current_token_count, current_time.isoformat()


def increment_usage_fixed_window(num_requests_str):
    num_requests = int(num_requests_str) if num_requests_str else 0
    num_requests += 1
    return num_requests


def increment_usage_sliding_window_log(current_time, timestamps_str):
    timestamps = timestamps_str.split("|||") if timestamps_str else []
    timestamps.append(current_time.isoformat())
    return "|||".join(timestamps)


def increment_usage_sliding_window_counter(window_size, log):
    time_window_start_str = log["time_window_start"]
    num_requests = int(log.get(time_window_start_str, "0"))

    updated_log = dict(log)
    updated_log[time_window_start_str] = str(num_requests + 1)

    # Purge all timestamps prior to the current time window and the previous 3 time windows (soft redundancy)
    valid_keys = ["time_window_start", time_window_start_str]
    time_window_start_reference = datetime.datetime.fromisoformat(time_window_start_str)

    for _ in range(3):
        time_window_start_reference -= datetime.timedelta(seconds=window_size)
        valid_keys.append(time_window_start_reference.isoformat())

    purged_log = {key: updated_log[key] for key in valid_keys if key in updated_log}
    return purged_log