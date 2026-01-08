import datetime

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
    
    try:
        log = retrieve_hash(key) or {}

        # utilize algorithm logic to decide whether or not request should be allowed
        if algorithm == "token_bucket":
            # token bucket: bucket size, refill rate (seconds)
                # retrieve last_request_time
                # calculate the amount of tokens that should be in the bucket utlizing last_request_time, current_bucket_size, and refill_rate (window_size)
                # if there is a token available then allow request
            bucket_size = window_size
            refill_rate = rate_limit
            # if there is no request time assume a last request time that would completely reset the token bucket
            last_request_time_str = log.get("last_request_time")
            if last_request_time_str:
                last_request_time = datetime.datetime.fromisoformat(last_request_time_str)
            else:
                last_request_time = current_time - datetime.timedelta(seconds=(bucket_size*refill_rate+1))
            
            last_token_count = int(log.get("last_token_count", 0))

            seconds_since_last_request = (current_time - last_request_time).total_seconds()

            tokens_to_be_added = int(seconds_since_last_request / refill_rate)
            current_token_count = last_token_count + tokens_to_be_added
            if current_token_count > bucket_size:
                current_token_count = bucket_size

            if current_token_count > 0:
                is_allowed = True
                
            # update the cache with new state (but don't consume token yet)
            log["last_request_time"] = current_time.isoformat()
            log["last_token_count"] = str(current_token_count)
            
            # store updated state in Redis
            store_hash(key, log, window_size + 60)
        elif algorithm == "fixed_window":
            # fixed window counter: request_limit, time window (seconds)
                # retrieve time_window_start and num_requests
                # if there is no time_window_start define the start as now and num_requests as 0
                # if the time_window_start + the time_window (window size) is less than the current time reset time_window (base it off of the original time_window_start) and num_requests
                # if num_requests < request_limit (rate_limit) then allow request
            time_window_start_str = log.get("time_window_start")
            if time_window_start_str:
                time_window_start = datetime.datetime.fromisoformat(time_window_start_str)
                num_requests = int(log.get("num_requests", "0"))
            else:
                time_window_start = current_time
                num_requests = 0

            while time_window_start + datetime.timedelta(seconds=window_size) < current_time:
                time_window_start += datetime.timedelta(seconds=window_size)
                num_requests = 0
            
            if num_requests < rate_limit:
                is_allowed = True
            
            # update the cache with new state (but don't consume request yet)
            log["time_window_start"] = time_window_start.isoformat()
            log["num_requests"] = str(num_requests)
            
            # store updated state in Redis
            store_hash(key, log, window_size + 60)
        elif algorithm == "sliding_window_log":
            # sliding window log: request_limit, time window
                # retrieve all timestamps
                # remove the timestamps that are older than current_time - window_size
                # if the number of timestamps left + 1 are less than or equal to rate_limit then allow request
            timestamps_str = log.get("timestamps", "")
            
            timestamps = timestamps_str.split("|||") if timestamps_str else []
            window_start = current_time - datetime.timedelta(seconds=window_size)

            trimmed_timestamps = []

            for timestamp_string in timestamps:
                if window_start > datetime.datetime.fromisoformat(timestamp_string):
                    continue 
                trimmed_timestamps.append(timestamp_string)
            
            if len(trimmed_timestamps) + 1 <= rate_limit:
                is_allowed = True

            # update the cache with new state (but don't consume request yet)
            log["timestamps"] = "|||".join(trimmed_timestamps)
            
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
            
        # sliding window counter:   request_limit, time window
            # calculate current window ID: current_time
            # get previous window ID: current_window - 1
            # retrieve counts: current_window_requests, prev_window_requests
            # calculate overlap ratio: (window_size - (current_time % window_size)) / window_size
            # estimate total: prev_count * overlap_ratio + current_count
            # if estimated_total < rate_limit then allow request
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
            current_token_count = int(log.get("last_token_count", 0))
            if current_token_count > 0:
                current_token_count -= 1
                log["last_token_count"] = str(current_token_count)
                log["last_request_time"] = current_time.isoformat()
                
                # store updated state in Redis
                store_hash(key, log, window_size + 60)
        elif was_allowed and algorithm == "fixed_window":
            # Increment num_requests after successful request
            num_requests = int(log.get("num_requests", "0"))
            num_requests += 1
            log["num_requests"] = str(num_requests)
            
            # store updated state in Redis
            store_hash(key, log, window_size + 60)
        elif algorithm == "sliding_window_log":
            # Add current time to timestamps log no matter what
            timestamps_str = log.get("timestamps", "")
            timestamps = timestamps_str.split("|||") if timestamps_str else []
            timestamps.append(current_time.isoformat())
            log["timestamps"] = "|||".join(timestamps)
            
            # store updated state in Redis
            store_hash(key, log, window_size + 60)
    finally:
        # always release the lock
        release_lock(lock_key)