import json
import os
import redis

cache = redis.Redis(
        host="cache",
        port=6379,
        password=os.getenv("REDIS_PASSWORD"),
        decode_responses=True
    )

def retrieve_value(key):
    cached_value = cache.get(key)
    return cached_value

def store_value(key, value, ttl):
    cache.setex(key, ttl, value)

def increment_value(key):
    cache.incr(key)

def decrement_value(key):
    cache.decr(key)