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

def retrieve_hash(key):
    return cache.hgetall(key)

def store_hash(key, hash_dict, ttl):
    pipe = cache.pipeline()
    pipe.hset(key, mapping=hash_dict)
    if ttl:
        pipe.expire(key, ttl)
    pipe.execute()

def acquire_lock(lock_key, timeout=5):
    return cache.set(lock_key, "1", nx=True, ex=timeout)

def release_lock(lock_key):
    cache.delete(lock_key)