def check_if_request_is_allowed(
    domain,
    category,
    identifier,
    user_id,
    password,
    current_time
):
    # validate user credentials

    # retrieve rate_limit, window_size, and algorithm

    # retrieve information about current usage from Redis with defaults defined 

    # utilize algorithm logic to decide whether or not request should be allowed

        # token bucket:         bucket size, refill rate (seconds)
            # retrieve last_request_time and current_bucket_size
            # calculate the amount of tokens that should be in the bucket utlizing last_request_time, current_bucket_size, and refill_rate (window_size)
            # if there is a token available then allow request

        # leaking bucket:       bucket size, outflow rate (seconds)
            # retrieve bucket_urls
            # if the amount of urls is less than the bucket size (window size) then allow request

                # # In redirect endpoint
                # if algorithm == "leaky_bucket":
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

        # fixed window counter: request_limit, time window (seconds)
            # retrieve time_window_start and num_requests
            # if there is no time_window_start define the start as now and num_requests as 0
            # if the time_window_start + the time_window (window size) is greater than the current time reset time_window (base it off of the original time_window_start) and num_requests
            # if num_requests < request_limit (rate_limit) then allow request

        # sliding window log:   request_limit, time window
            # retrieve all timestamps
            # remove the timestamps that are older than current_time - window_size
            # if the number of timestamps left + 1 are less than or equal to window_size then allow request
            
        # sliding window counter:   request_limit, time window
            # calculate current window ID: current_time
            # get previous window ID: current_window - 1
            # retrieve counts: current_window_requests, prev_window_requests
            # calculate overlap ratio: (window_size - (current_time % window_size)) / window_size
            # estimate total: prev_count * overlap_ratio + current_count
            # if estimated_total < rate_limit then allow request
            
        # REFERENCE: examples of Redis utilization
            # INCLUDE ALGORITHM IN KEY

            # # Request counters
            # store_value("user:123:api:requests", "5", ttl=3600)
            # increment_value("user:123:api:requests")

            # # Window tracking  
            # store_value("user:123:api:window_start", "1625097600", ttl=3600)
        # return is_allowed, is_leaking_bucket
    pass

def increment_rate_limit_usage(domain, category, user_id, current_time):

    # retrieve rate_limit, time_window, and algorithm

    # increment rate limit usage with based on algorithm
    
    pass